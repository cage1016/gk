package generator

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/go-errors/errors"
	"github.com/kujtimiihoxha/gk/fs"
	"github.com/kujtimiihoxha/gk/parser"
	template "github.com/kujtimiihoxha/gk/templates"
	"github.com/kujtimiihoxha/gk/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/tools/imports"
)

var SUPPORTED_TRANSPORTS = []string{"http", "grpc", "thrift"}

type ServiceGenerator struct {
}

func (sg *ServiceGenerator) Generate(name string) error {
	logrus.Info(fmt.Sprintf("Generating service: %s", name))
	f := parser.NewFile()
	f.Package = "service"
	te := template.NewEngine()
	iname, err := te.ExecuteString(viper.GetString("service.interface_name"), map[string]string{
		"ServiceName": name,
	})
	logrus.Debug(fmt.Sprintf("Service interface name : %s", iname))
	if err != nil {
		return err
	}
	f.Interfaces = []parser.Interface{
		parser.NewInterfaceWithComment(iname, fmt.Sprintf(`%s implements yor service methods.
		e.x: Foo(ctx context.Context,s string)(rs string, err error)`, iname), []parser.Method{}),
	}
	defaultFs := fs.Get()

	path, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	logrus.Debug(fmt.Sprintf("Service path: %s", path))
	if err != nil {
		return err
	}
	b, err := defaultFs.Exists(path)
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
		"ServiceName": name,
	})
	logrus.Debug(fmt.Sprintf("Service file name: %s", fname))
	if err != nil {
		return err
	}
	if b {
		logrus.Debug("Service folder already exists")
		return fs.NewDefaultFs(path).WriteFile(fname, f.String(), false)
	}
	err = defaultFs.MkdirAll(path)
	logrus.Debug(fmt.Sprintf("Creating folder structure : %s", path))
	if err != nil {
		return err
	}
	return fs.NewDefaultFs(path).WriteFile(fname, f.String(), false)
}
func NewServiceGenerator() *ServiceGenerator {
	return &ServiceGenerator{}
}

type CMDGenerator struct {
}

func (cg *CMDGenerator) Generate(name string) error {
	g := NewCMDGenerator()
	te := template.NewEngine()
	defaultFs := fs.Get()
	path, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	sfile := path + defaultFs.FilePathSeparator() + fname
	b, err := defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	iname, err := te.ExecuteString(viper.GetString("service.interface_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Service %s was not found", name))
	}
	p := parser.NewFileParser()
	s, err := defaultFs.ReadFile(sfile)
	if err != nil {
		return err
	}
	f, err := p.Parse([]byte(s))
	if err != nil {
		return err
	}
	var iface *parser.Interface
	for _, v := range f.Interfaces {
		if v.Name == iname {
			iface = &v
		}
	}
	if iface == nil {
		return errors.New(fmt.Sprintf("Could not find the service interface in `%s`", sfile))
	}
	toKeep := []parser.Method{}
	for _, v := range iface.Methods {
		isOk := false
		for _, p := range v.Parameters {
			if p.Type == "context.Context" {
				isOk = true
				break
			}
		}
		if string(v.Name[0]) == strings.ToLower(string(v.Name[0])) {
			logrus.Warnf("The method '%s' is private and will be ignored", v.Name)
			continue
		}
		if len(v.Results) == 0 {
			logrus.Warnf("The method '%s' does not have any return value and will be ignored", v.Name)
			continue
		}
		if !isOk {
			logrus.Warnf("The method '%s' does not have a context and will be ignored", v.Name)
		}
		if isOk {
			toKeep = append(toKeep, v)
		}

	}
	iface.Methods = toKeep
	if len(iface.Methods) == 0 {
		return errors.New("The service has no method please implement the interface methods")
	}
	return g.generateCMD(name, iface)
}
func (cg *CMDGenerator) generateCMD(name string, iface *parser.Interface) error {
	logrus.Info("Generating cmd main...")
	te := template.NewEngine()
	defaultFs := fs.Get()
	mainFile := parser.NewFile()
	mainFile.Package = "main"

	//
	var projectPath string
	goModPackage := utils.GetModPackage()
	if goModPackage == "" {
		gosrc := utils.GetGOPATH() + "/src/"
		gosrc = strings.Replace(gosrc, "\\", "/", -1)
		pwd, err := os.Getwd()
		if err != nil {
			return err
		}
		if viper.GetString("gk_folder") != "" {
			pwd += "/" + viper.GetString("gk_folder")
		}
		pwd = strings.Replace(pwd, "\\", "/", -1)
		projectPath = strings.Replace(pwd, gosrc, "", 1)
	} else {
		projectPath = goModPackage
	}

	// endpoints import
	enpointsPath, err := te.ExecuteString(viper.GetString("endpoints.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	enpointsPath = strings.Replace(enpointsPath, "\\", "/", -1)
	endpointsImport := projectPath + "/" + enpointsPath

	// service import
	servicePath, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	servicePath = strings.Replace(servicePath, "\\", "/", -1)
	serviceImport := projectPath + "/" + servicePath

	// transports import
	transportsPath, err := te.ExecuteString(viper.GetString("transports.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	transportsPath = strings.Replace(transportsPath, "\\", "/", -1)
	transportsImport := projectPath + "/" + transportsPath

	mainFile.Imports = []parser.NamedTypeValue{
		parser.NewNameType("", "\"fmt\""),
		parser.NewNameType("", "\"log\""),
		parser.NewNameType("", "\"net\""),
		parser.NewNameType("", "\"net/http\""),
		parser.NewNameType("", "\"os\""),
		parser.NewNameType("", "\"os/signal\""),
		parser.NewNameType("", "\"strconv\""),
		parser.NewNameType("", "\"syscall\""),
		parser.NewNameType("", ""),
		parser.NewNameType("", "\"github.com/go-kit/kit/sd\""),
		parser.NewNameType("", "\"google.golang.org/grpc\""),
		parser.NewNameType("", "\"google.golang.org/grpc/credentials\""),
		parser.NewNameType("", "\"google.golang.org/grpc/health/grpc_health_v1\""),
		parser.NewNameType("", ""),
		parser.NewNameType("", "\""+projectPath+"\""),
		parser.NewNameType("", "\""+endpointsImport+"\""),
		parser.NewNameType("", "\""+serviceImport+"\""),
		parser.NewNameType("", "\""+transportsImport+"\""),
		parser.NewNameType("", "\"github.com/cage1016/gokitconsul/pkg/logger\""),
		parser.NewNameType("", "\"github.com/cage1016/gokitconsul/tools/localip\""),
		parser.NewNameType("", "\"github.com/cage1016/gokitconsul/pkg/consulregister\""),
		parser.NewNameType("", fmt.Sprintf(`"%s/pb/%s"`, projectPath, strings.ToLower(name))),
	}

	// constants
	{
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("serviceName", "string", fmt.Sprintf(`"%s"`, name)))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("tag", "string", `"gokitconsul"`))

		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defLogLevel", "string", `"error"`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defConsulHost", "string", `"localhost"`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defConsulPort", "string", `"8500"`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defServiceHost", "string", `"localhost"`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defHTTPPort", "string", `"8180"`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defGRPCPort", "string", `"8181"`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defServerCert", "string", `""`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defServerKey", "string", `""`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defClientTLS", "string", `"false"`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defCACerts", "string", `""`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defZipkinV1URL", "string", `""`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defZipkinV2URL", "string", `""`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defLightstepToken", "string", `""`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("defAppdashAddr", "string", `""`))

		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envLogLevel", "string", fmt.Sprintf(`"QS_%s_LOG_LEVEL"`, strings.ToUpper(name))))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envConsulHost", "string", `"QS_CONSULT_HOST"`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envConsultPort", "string", `"QS_CONSULT_PORT"`))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envServiceHost", "string", fmt.Sprintf(`"QS_%s_SERVICE_HOST"`, strings.ToUpper(name))))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envHTTPPort", "string", fmt.Sprintf(`"QS_%s_HTTP_PORT"`, strings.ToUpper(name))))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envGRPCPort", "string", fmt.Sprintf(`"QS_%s_GRPC_PORT"`, strings.ToUpper(name))))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envServerCert", "string", fmt.Sprintf(`"QS_%s_SERVER_CERT"`, strings.ToUpper(name))))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envServerKey", "string", fmt.Sprintf(`"QS_%s_SERVER_KEY"`, strings.ToUpper(name))))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envClientTLS", "string", fmt.Sprintf(`"QS_%s_CLIENT_TLS"`, strings.ToUpper(name))))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envCACerts", "string", fmt.Sprintf(`"QS_%s_CA_CERTS"`, strings.ToUpper(name))))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envZipkinV1URL", "string", fmt.Sprintf(`"QS_%s_ZIPKIN_V1_URL"`, strings.ToUpper(name))))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envZipkinV2URL", "string", fmt.Sprintf(`"QS_%s_ZIPKIN_V2_URL"`, strings.ToUpper(name))))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envLightstepToken", "string", fmt.Sprintf(`"QS_%s_LIGHT_STEP_TOKEN"`, strings.ToUpper(name))))
		mainFile.Constants = append(mainFile.Constants, parser.NewNameTypeValue("envAppdashAddr", "string", fmt.Sprintf(`"QS_%s_APPDASH_ADDR"`, strings.ToUpper(name))))
	}

	// config struct
	configStrct := parser.NewStruct("config", []parser.NamedTypeValue{})
	configStrct.Name = "config"
	vars := []parser.NamedTypeValue{
		parser.NewNameType("logLevel", "string"),
		parser.NewNameType("clientTLS", "bool"),
		parser.NewNameType("caCerts", "string"),
		parser.NewNameType("serviceHost", "string"),
		parser.NewNameType("httpPort", "string"),
		parser.NewNameType("grpcPort", "string"),
		parser.NewNameType("serverCert", "string"),
		parser.NewNameType("serverKey", "string"),
		parser.NewNameType("consulHost", "string"),
		parser.NewNameType("consultPort", "string"),
		parser.NewNameType("zipkinV1URL", "string"),
		parser.NewNameType("zipkinV2URL", "string"),
		parser.NewNameType("lightstepToken", "string"),
		parser.NewNameType("appdashAddr", "string"),
	}
	configStrct.Vars = append(configStrct.Vars, vars...)
	mainFile.Structs = append(mainFile.Structs, configStrct)

	// main function
	mainFile.Methods = append(mainFile.Methods, parser.NewMethod(
		"main",
		parser.NamedTypeValue{},
		`	cfg := loadConfig()
				errs := make(chan error, 2)

				logger, err := logger.New(os.Stdout, cfg.logLevel)
				if err != nil {
					log.Fatalf(err.Error())
				}

				consulAddres := fmt.Sprintf("%s:%s", cfg.consulHost, cfg.consultPort)
				serviceIp := localip.LocalIP()
				servicePort, _ := strconv.Atoi(cfg.grpcPort)
				consulReg := consulregister.NewConsulRegister(consulAddres, serviceName, serviceIp, servicePort, []string{serviceName, tag}, logger)
				svcRegistar, err := consulReg.NewConsulGRPCRegister()
				if err != nil {
					log.Fatalf(err.Error())
				}

				service := service.New()
				endpoints := endpoints.New(service)
				httpHandler := transports.NewHTTPHandler(endpoints)
				grpcServer := transports.MakeGRPCServer(endpoints)

				go startHTTPServer(httpHandler, cfg.httpPort, cfg.serverCert, cfg.serverKey, logger, errs)
				go startGRPCServer(svcRegistar, grpcServer, cfg.grpcPort, cfg.serverCert, cfg.serverKey, logger, errs)

				go func() {
					c := make(chan os.Signal)
					signal.Notify(c, syscall.SIGINT)
					errs <- fmt.Errorf("%s", <-c)
				}()

				err = <-errs
				logger.Error(fmt.Sprintf("%s service terminated: %s", serviceName, err))`,
		[]parser.NamedTypeValue{},
		[]parser.NamedTypeValue{},
	))

	// loadConfig function
	loadConfigFunc := parser.NewMethod(
		"loadConfig",
		parser.NamedTypeValue{},
		`tls, err := strconv.ParseBool(gokitconsul.Env(envClientTLS, defClientTLS))
				if err != nil {
					log.Fatalf("Invalid value passed for %s\n", envClientTLS)
				}

				return config{
					logLevel:       gokitconsul.Env(envLogLevel, defLogLevel),
					clientTLS:      tls,
					caCerts:        gokitconsul.Env(envCACerts, defCACerts),
					serviceHost:    gokitconsul.Env(envServiceHost, defServiceHost),
					httpPort:       gokitconsul.Env(envHTTPPort, defHTTPPort),
					grpcPort:       gokitconsul.Env(envGRPCPort, defGRPCPort),
					serverCert:     gokitconsul.Env(envServerCert, defServerCert),
					serverKey:      gokitconsul.Env(envServerKey, defServerKey),
					consulHost:     gokitconsul.Env(envConsulHost, defConsulHost),
					consultPort:    gokitconsul.Env(envConsultPort, defConsulPort),
					zipkinV1URL:    gokitconsul.Env(envZipkinV1URL, defZipkinV1URL),
					zipkinV2URL:    gokitconsul.Env(envZipkinV2URL, defZipkinV2URL),
					lightstepToken: gokitconsul.Env(envLightstepToken, defLightstepToken),
					appdashAddr:    gokitconsul.Env(envAppdashAddr, defAppdashAddr),
				}`,
		[]parser.NamedTypeValue{},
		[]parser.NamedTypeValue{
			parser.NewNameType("", "config"),
		},
	)
	mainFile.Methods = append(mainFile.Methods, loadConfigFunc)

	// startHTTPServer
	mainFile.Methods = append(mainFile.Methods, parser.NewMethod(
		"startHTTPServer",
		parser.NamedTypeValue{},
		`p := fmt.Sprintf(":%s", port)
				if certFile != "" || keyFile != "" {
					logger.Info(fmt.Sprintf("%s service started using https, cert %s key %s, exposed port %s", serviceName, certFile, keyFile, port))
					errs <- http.ListenAndServeTLS(p, certFile, keyFile, httpHandler)
				} else {
					logger.Info(fmt.Sprintf("%s service started using http, exposed port %s", serviceName, port))
					errs <- http.ListenAndServe(p, httpHandler)
				}`,
		[]parser.NamedTypeValue{
			parser.NewNameType("httpHandler", "http.Handler"),
			parser.NewNameType("port", "string"),
			parser.NewNameType("certFile", "string"),
			parser.NewNameType("keyFile", "string"),
			parser.NewNameType("logger", "logger.Logger"),
			parser.NewNameType("errs", "chan error"),
		},
		[]parser.NamedTypeValue{},
	))

	// startGRPCServer
	body := `	p := fmt.Sprintf(":%s", port)
				listener, err := net.Listen("tcp", p)
				if err != nil {
					logger.Error(fmt.Sprintf("Failed to listen on port %s: %s", port, err))
				}

				var server *grpc.Server
				if certFile != "" || keyFile != "" {
					creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
					if err != nil {
						logger.Error(fmt.Sprintf("Failed to load %s certificates: %s", serviceName, err))
						os.Exit(1)
					}
					logger.Info(fmt.Sprintf("%s gRPC service started using https on port %s with cert %s key %s", serviceName, port, certFile, keyFile))
					server = grpc.NewServer(grpc.Creds(creds))
				} else {
					logger.Info(fmt.Sprintf("%s gRPC service started using http on port %s", serviceName, port))
					server = grpc.NewServer()
				}
				//grpc_health_v1.RegisterHealthServer(server, service.NewStubXxxService())`
	body += "\n" + fmt.Sprintf(`pb.Register%sServer(server, grpcServer)`, utils.ToUpperFirstCamelCase(name))
	body += "\n" + `registar.Register()
				logger.Info(fmt.Sprintf("%s gRPC service started, exposed port %s", serviceName, port))
				errs <- server.Serve(listener)`
	mainFile.Methods = append(mainFile.Methods, parser.NewMethod(
		"startGRPCServer",
		parser.NamedTypeValue{},
		body,
		[]parser.NamedTypeValue{
			parser.NewNameType("registar", "sd.Registrar"),
			parser.NewNameType("grpcServer", fmt.Sprintf("pb.%sServer", utils.ToUpperFirstCamelCase(name))),
			parser.NewNameType("port", "string"),
			parser.NewNameType("certFile", "string"),
			parser.NewNameType("keyFile", "string"),
			parser.NewNameType("logger", "logger.Logger"),
			parser.NewNameType("errs", "chan error"),
		},
		[]parser.NamedTypeValue{},
	))

	//
	path, err := te.ExecuteString(viper.GetString("cmd.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	b, err := defaultFs.Exists(path)
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("cmd.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	tfile := path + defaultFs.FilePathSeparator() + fname
	if b {
		//fex, err := defaultFs.Exists(tfile)
		//if err != nil {
		//	return err
		//}
		//if fex {
		//	logrus.Errorf("Cdm main for service `%s` exist", name)
		//	logrus.Info("If you are trying to update a service use `gk update service [serviceName] TOBE DONE`")
		//	return nil
		//}
	} else {
		err = defaultFs.MkdirAll(path)
		if err != nil {
			return err
		}
	}

	return defaultFs.WriteFile(tfile, mainFile.String(), false)
}

func NewCMDGenerator() *CMDGenerator {
	return &CMDGenerator{}
}

type MiddlewareGenerator struct {
}

func (mg *MiddlewareGenerator) Generate(name string) error {
	g := NewMiddlewareGenerator()
	te := template.NewEngine()
	defaultFs := fs.Get()

	sfname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	spath, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	epath, err := te.ExecuteString(viper.GetString("endpoints.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	sfile := spath + defaultFs.FilePathSeparator() + sfname
	b, err := defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	iname, err := te.ExecuteString(viper.GetString("service.interface_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Service %s was not found", name))
	}
	p := parser.NewFileParser()
	s, err := defaultFs.ReadFile(sfile)
	if err != nil {
		return err
	}
	f, err := p.Parse([]byte(s))
	if err != nil {
		return err
	}
	var iface *parser.Interface
	for _, v := range f.Interfaces {
		if v.Name == iname {
			iface = &v
		}
	}
	if iface == nil {
		return errors.New(fmt.Sprintf("Could not find the service interface in `%s`", sfile))
	}
	toKeep := []parser.Method{}
	for _, v := range iface.Methods {
		isOk := false
		for _, p := range v.Parameters {
			if p.Type == "context.Context" {
				isOk = true
				break
			}
		}
		if string(v.Name[0]) == strings.ToLower(string(v.Name[0])) {
			logrus.Warnf("The method '%s' is private and will be ignored", v.Name)
			continue
		}
		if len(v.Results) == 0 {
			logrus.Warnf("The method '%s' does not have any return value and will be ignored", v.Name)
			continue
		}
		if !isOk {
			logrus.Warnf("The method '%s' does not have a context and will be ignored", v.Name)
		}
		if isOk {
			toKeep = append(toKeep, v)
		}

	}
	iface.Methods = toKeep
	if len(iface.Methods) == 0 {
		return errors.New("The service has no method please implement the interface methods")
	}
	err = g.generateServiceMiddleware(name, spath, iface)
	if err != nil {
		return err
	}
	err = g.generateEndpointMiddleware(name, epath, iface)
	if err != nil {
		return err
	}
	return nil
}
func (mg *MiddlewareGenerator) generateEndpointMiddleware(name, path string, iface *parser.Interface) error {
	logrus.Info("Generating endpoints middleware...")
	te := template.NewEngine()
	defaultFs := fs.Get()
	handlerFile := parser.NewFile()
	handlerFile.Package = "endpoints"

	//
	mname, err := te.ExecuteString(viper.GetString("middleware.name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	// imports
	handlerFile.Imports = []parser.NamedTypeValue{
		parser.NewNameType("", "\"github.com/go-kit/kit/endpoint\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/metrics\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/log\""),
	}

	// LoggingMiddleware
	handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
		"LoggingMiddleware",
		`LoggingMiddleware returns an endpoint middleware that logs the
					duration of each invocation, and the resulting error, if any.`,
		parser.NamedTypeValue{},
		`return func(next endpoint.Endpoint) endpoint.Endpoint {
					return func(ctx context.Context, request interface{}) (response interface{}, err error) {
						defer func(begin time.Time) {
							logger.Log("transport_error", err, "took", time.Since(begin))
						}(time.Now())
						return next(ctx, request)
					}
				}`,
		[]parser.NamedTypeValue{
			parser.NewNameType("logger", "log.Logger"),
		},
		[]parser.NamedTypeValue{
			parser.NewNameType("", "endpoint.Middleware"),
		},
	))

	// InstrumentingMiddleware
	handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
		"InstrumentingMiddleware",
		`InstrumentingMiddleware returns an endpoint middleware that records
					the duration of each invocation to the passed histogram. The middleware adds
					a single field: "success", which is "true" if no error is returned, and
					"false" otherwise.`,
		parser.NamedTypeValue{},
		`return func(next endpoint.Endpoint) endpoint.Endpoint {
					return func(ctx context.Context, request interface{}) (response interface{}, err error) {
						defer func(begin time.Time) {
							duration.With("success", fmt.Sprint(err == nil)).Observe(time.Since(begin).Seconds())
						}(time.Now())
						return next(ctx, request)
					}
				}`,
		[]parser.NamedTypeValue{
			parser.NewNameType("duration", "metrics.Histogram"),
		},
		[]parser.NamedTypeValue{
			parser.NewNameType("", "endpoint.Middleware"),
		},
	))

	tfile := path + defaultFs.FilePathSeparator() + mname
	//if b {
	//	fex, err := defaultFs.Exists(tfile)
	//	if err != nil {
	//		return err
	//	}
	//	if fex {
	//		logrus.Errorf("Transport for service `%s` exist", name)
	//		logrus.Info("If you are trying to update a service use `gk update service [serviceName]`")
	//		return nil
	//	}
	//} else {
	//	err = defaultFs.MkdirAll(path)
	//	if err != nil {
	//		return err
	//	}
	//}
	return defaultFs.WriteFile(tfile, handlerFile.String(), false)
}
func (mg *MiddlewareGenerator) generateServiceMiddleware(name, path string, iface *parser.Interface) error {
	logrus.Info("Generating service middleware...")
	te := template.NewEngine()
	defaultFs := fs.Get()
	handlerFile := parser.NewFile()
	handlerFile.Package = "service"

	//
	mname, err := te.ExecuteString(viper.GetString("middleware.name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	// import
	mim := []string{
		handlerFile.String(),
		"import (",
		`"github.com/go-kit/kit/metrics"`,
		`"github.com/go-kit/kit/log"`,
		`"google.golang.org/grpc/health/grpc_health_v1"`,
		")",
	}
	var s string
	s += strings.Join(mim, "\n")

	//
	t, err := template.NewEngine().ExecuteString("{{template \"struct_type\" .}}", struct {
		Name    string
		Comment string
		Type    string
	}{
		Name:    "Middleware",
		Comment: "// Middleware describes a service (as opposed to endpoint) middleware.",
		Type:    fmt.Sprintf("func(%sService) %sService", utils.ToUpperFirstCamelCase(name), utils.ToUpperFirstCamelCase(name)),
	})
	s += "\n" + t

	// LoggingMiddleware
	m := parser.NewMethodWithComment(
		"LoggingMiddleware",
		`LoggingMiddleware takes a logger as a dependency
			and returns a ServiceMiddleware.`,
		parser.NamedTypeValue{},
		fmt.Sprintf(`return func(next %sService) %sService {
								return loggingMiddleware{level.Info(logger), next}
							}`, utils.ToUpperFirstCamelCase(name), utils.ToUpperFirstCamelCase(name)),
		[]parser.NamedTypeValue{
			parser.NewNameType("logger", "log.Logger"),
		},
		[]parser.NamedTypeValue{
			parser.NewNameType("", "Middleware"),
		},
	)
	s += "\n" + m.String()

	t2 := parser.Struct{
		Name:    "loggingMiddleware",
		Comment: "",
		Vars: []parser.NamedTypeValue{
			parser.NewNameType("logger", "log.Logger"),
			parser.NewNameType("next", fmt.Sprintf("%sService", utils.ToUpperFirstCamelCase(name))),
		},
	}
	s += "\n" + t2.String()

	for _, v := range iface.Methods {
		reqPrams := []parser.NamedTypeValue{}
		for _, p := range v.Parameters {
			if p.Type != "context.Context" {
				//n := strings.ToUpper(string(p.Name[0])) + p.Name[1:]
				reqPrams = append(reqPrams, parser.NewNameType(p.Name, p.Type))
			}
		}
		resultPrams := []parser.NamedTypeValue{}
		for _, p := range v.Results {
			//n := strings.ToUpper(string(p.Name[0])) + p.Name[1:]
			resultPrams = append(resultPrams, parser.NewNameType(p.Name, p.Type))
		}
		req := parser.NewStructWithComment(
			v.Name+"Request",
			fmt.Sprintf(
				"%sRequest collects the request parameters for the %s method.",
				v.Name, v.Name,
			),
			reqPrams,
		)
		res := parser.NewStructWithComment(
			v.Name+"Response",
			fmt.Sprintf(
				"%sResponse collects the response values for the %s method.",
				v.Name, v.Name,
			),
			resultPrams,
		)
		tmplModel := map[string]interface{}{
			"Calling":  v,
			"Request":  req,
			"Response": res,
		}
		tRes, err := te.ExecuteString("{{template \"middleware_logging\" .}}", tmplModel)
		if err != nil {
			return err
		}

		t3 := parser.NewMethod(
			v.Name,
			parser.NamedTypeValue{Name: "lm", Type: "loggingMiddleware"},
			tRes,
			v.Parameters,
			v.Results,
		)
		s += "\n\n" + t3.String()
	}

	// InstrumentingMiddleware
	var x []string
	var y []parser.NamedTypeValue
	for _, v := range iface.Methods {
		x = append(x, fmt.Sprintf("%s: %s,", strings.ToLower(v.Name), strings.ToLower(v.Name)))
		y = append(y, parser.NewNameType(strings.ToLower(v.Name), "metrics.Counter"), )
	}
	m = parser.NewMethodWithComment(
		"InstrumentingMiddleware",
		`InstrumentingMiddleware returns a service middleware that instruments
					the number of integers summed and characters concatenated over the lifetime of
					the service.`,
		parser.NamedTypeValue{},
		fmt.Sprintf(`return func(next %sService) %sService {
								return instrumentingMiddleware{
									%s
									next:  next,
								}
							}`, utils.ToUpperFirstCamelCase(name), utils.ToUpperFirstCamelCase(name), strings.Join(x, "\n")),
		y,
		[]parser.NamedTypeValue{
			parser.NewNameType("", "Middleware"),
		},
	)
	s += "\n" + m.String()

	//
	t2 = parser.Struct{
		Name:    "instrumentingMiddleware",
		Comment: "",
		Vars:    append(y, parser.NewNameType("next", fmt.Sprintf("%sService", utils.ToUpperFirstCamelCase(name))), ),
	}
	s += "\n" + t2.String()

	for _, v := range iface.Methods {
		reqPrams := []parser.NamedTypeValue{}
		for _, p := range v.Parameters {
			if p.Type != "context.Context" {
				//n := strings.ToUpper(string(p.Name[0])) + p.Name[1:]
				reqPrams = append(reqPrams, parser.NewNameType(p.Name, p.Type))
			}
		}
		resultPrams := []parser.NamedTypeValue{}
		for _, p := range v.Results {
			//n := strings.ToUpper(string(p.Name[0])) + p.Name[1:]
			resultPrams = append(resultPrams, parser.NewNameType(p.Name, p.Type))
		}
		req := parser.NewStructWithComment(
			v.Name+"Request",
			fmt.Sprintf(
				"%sRequest collects the request parameters for the %s method.",
				v.Name, v.Name,
			),
			reqPrams,
		)
		res := parser.NewStructWithComment(
			v.Name+"Response",
			fmt.Sprintf(
				"%sResponse collects the response values for the %s method.",
				v.Name, v.Name,
			),
			resultPrams,
		)
		tmplModel := map[string]interface{}{
			"Calling":  v,
			"Request":  req,
			"Response": res,
		}
		tRes, err := te.ExecuteString("{{template \"middleware_instrumenting\" .}}", tmplModel)
		if err != nil {
			return err
		}
		t3 := parser.NewMethod(
			v.Name,
			parser.NamedTypeValue{Name: "im", Type: "instrumentingMiddleware"},
			tRes,
			v.Parameters,
			v.Results,
		)
		s += "\n\n" + t3.String()
	}

	tfile := path + defaultFs.FilePathSeparator() + mname
	//fex, err := defaultFs.Exists(tfile)
	//if err != nil {
	//	return err
	//}
	//if fex {
	//	logrus.Errorf("Middleware for service `%s` exist", name)
	//	logrus.Info("If you are trying to update a Middleware use `gk update middleware [serviceName]`")
	//	return nil
	//}

	d, err := imports.Process("g", []byte(s), nil)
	if err != nil {
		return err
	}

	return defaultFs.WriteFile(tfile, string(d), true)
}

func NewMiddlewareGenerator() *MiddlewareGenerator {
	return &MiddlewareGenerator{}
}

type ServiceInitGenerator struct {
}

func (sg *ServiceInitGenerator) Generate(name string) error {
	te := template.NewEngine()
	defaultFs := fs.Get()

	// project path
	//var projectPath string
	//goModPackage := utils.GetModPackage()
	//if goModPackage == "" {
	//	gosrc := utils.GetGOPATH() + "/src/"
	//	gosrc = strings.Replace(gosrc, "\\", "/", -1)
	//	pwd, err := os.Getwd()
	//	if err != nil {
	//		return err
	//	}
	//	if viper.GetString("gk_folder") != "" {
	//		pwd += "/" + viper.GetString("gk_folder")
	//	}
	//	pwd = strings.Replace(pwd, "\\", "/", -1)
	//	projectPath = strings.Replace(pwd, gosrc, "", 1)
	//} else {
	//	projectPath = goModPackage
	//}

	path, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	sfile := path + defaultFs.FilePathSeparator() + fname
	b, err := defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	iname, err := te.ExecuteString(viper.GetString("service.interface_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Service %s was not found", name))
	}
	transport := viper.GetString("gk_transport")
	supported := false
	for _, v := range SUPPORTED_TRANSPORTS {
		if v == transport {
			supported = true
			break
		}
	}
	if !supported {
		return errors.New(fmt.Sprintf("Transport `%s` not supported", transport))
	}

	p := parser.NewFileParser()
	s, err := defaultFs.ReadFile(sfile)
	if err != nil {
		return err
	}
	f, err := p.Parse([]byte(s))
	if err != nil {
		return err
	}
	var iface *parser.Interface
	for _, v := range f.Interfaces {
		if v.Name == iname {
			iface = &v
		}
	}
	if iface == nil {
		return errors.New(fmt.Sprintf("Could not find the service interface in `%s`", sfile))
	}
	toKeep := []parser.Method{}
	for _, v := range iface.Methods {
		isOk := false
		for _, p := range v.Parameters {
			if p.Type == "context.Context" {
				isOk = true
				break
			}
		}
		if string(v.Name[0]) == strings.ToLower(string(v.Name[0])) {
			logrus.Warnf("The method '%s' is private and will be ignored", v.Name)
			continue
		}
		if len(v.Results) == 0 {
			logrus.Warnf("The method '%s' does not have any return value and will be ignored", v.Name)
			continue
		}
		if !isOk {
			logrus.Warnf("The method '%s' does not have a context and will be ignored", v.Name)
		}
		if isOk {
			toKeep = append(toKeep, v)
		}

	}
	iface.Methods = toKeep
	if len(iface.Methods) == 0 {
		return errors.New("The service has no suitable methods please implement the interface methods")
	}

	stubName, err := te.ExecuteString(viper.GetString("service.struct_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	stub := parser.NewStruct(stubName, []parser.NamedTypeValue{})
	exists := false
	for _, v := range f.Structs {
		if v.Name == stub.Name {
			logrus.Infof("Service `%s` structure already exists so it will not be recreated.", stub.Name)
			exists = true
		}
	}
	if !exists {
		s += "\n" + stub.String()

		stubMethod := parser.NewMethodWithComment(
			fmt.Sprintf("New%s", utils.ToUpperFirstCamelCase(stub.Name)),
			fmt.Sprintf(`New%s returns a naïve, stateless implementation of Service.`, utils.ToUpperFirstCamelCase(stub.Name)),
			parser.NamedTypeValue{},
			fmt.Sprintf("return &%s{}", stub.Name),
			[]parser.NamedTypeValue{},
			[]parser.NamedTypeValue{
				parser.NewNameType("", iname),
			},
		)
		s += "\n" + stubMethod.String()
	}
	exists = false
	for _, v := range f.Methods {
		if v.Name == "New" {
			logrus.Infof("Service `%s` New function already exists so it will not be recreated", stub.Name)
			exists = true
		}
	}

	if !exists {
		req := []parser.NamedTypeValue{
			//parser.NewNameType("logger", "logger.Logger"),
		}
		//ms := []string{}
		//for _, v := range iface.Methods {
		//	req = append(req, parser.NewNameType(strings.ToLower(v.Name), "metrics.Counter"))
		//	ms = append(ms, strings.ToLower(v.Name))
		//}

		body := []string{
			fmt.Sprintf("var svc %s", iname),
			"{",
			fmt.Sprintf("svc = &%s{}", stub.Name),
			//"svc = LoggingMiddleware(logger)(svc)",
			//fmt.Sprintf("svc = InstrumentingMiddleware(%s)(svc)", strings.Join(ms, ",")),
			"}",
			"return svc",
		}

		newMethod := parser.NewMethodWithComment(
			"New",
			`New return a new instance of the service.
			If you want to add service middleware this is the place to put them.`,
			parser.NamedTypeValue{},
			strings.Join(body, "\n"),
			req,
			[]parser.NamedTypeValue{
				parser.NewNameType("s", iname),
			},
		)
		s += "\n" + newMethod.String()
	}
	for _, m := range iface.Methods {
		exists = false
		m.Struct = parser.NewNameType(strings.ToLower(iface.Name[:2]), "*"+stub.Name)
		for _, v := range f.Methods {
			if v.Name == m.Name && v.Struct.Type == m.Struct.Type {
				logrus.Infof("Service method `%s` already exists so it will not be recreated.", v.Name)
				exists = true
			}
		}
		if !exists {
			x := parser.NewMethodWithComment(
				m.Name,
				fmt.Sprintf(`Implement the business logic of %s`, m.Name),
				parser.NewNameType(strings.ToLower(iface.Name[:2]), "*"+stub.Name),
				"",
				m.Parameters,
				m.Results,
			)

			s += "\n" + x.String()
		}
	}
	d, err := imports.Process("g", []byte(s), nil)
	if err != nil {
		return err
	}
	err = defaultFs.WriteFile(sfile, string(d), true)
	if err != nil {
		return err
	}
	err = sg.generateEndpoints(name, iface)
	if err != nil {
		return err
	}
	err = sg.generateTransport(name, iface, transport)
	if err != nil {
		return err
	}
	return nil
}

func (sg *ServiceInitGenerator) generateTransport(name string, iface *parser.Interface, transport string) error {
	switch transport {
	case "http":
		logrus.Info("Selected http transport.")
		return sg.generateHttpTransport(name, iface)
	case "grpc":
		logrus.Info("Selected grpc transport.")
		return sg.generateGRPCTransport(name, iface)
	case "thrift":
		logrus.Info("Selected thrift transport.")
		return sg.generateThriftTransport(name, iface)
	default:
		return errors.New(fmt.Sprintf("Transport `%s` not supported", transport))
	}
}
func (sg *ServiceInitGenerator) generateHttpTransport(name string, iface *parser.Interface) error {
	logrus.Info("Generating http transport...")
	te := template.NewEngine()
	defaultFs := fs.Get()
	handlerFile := parser.NewFile()
	handlerFile.Package = "transports"

	//
	var projectPath string
	goModPackage := utils.GetModPackage()
	if goModPackage == "" {
		gosrc := utils.GetGOPATH() + "/src/"
		gosrc = strings.Replace(gosrc, "\\", "/", -1)
		pwd, err := os.Getwd()
		if err != nil {
			return err
		}
		if viper.GetString("gk_folder") != "" {
			pwd += "/" + viper.GetString("gk_folder")
		}
		pwd = strings.Replace(pwd, "\\", "/", -1)
		projectPath = strings.Replace(pwd, gosrc, "", 1)
	} else {
		projectPath = goModPackage
	}

	enpointsPath, err := te.ExecuteString(viper.GetString("endpoints.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	enpointsPath = strings.Replace(enpointsPath, "\\", "/", -1)
	endpointsImport := projectPath + "/" + enpointsPath

	servicePath, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	servicePath = strings.Replace(servicePath, "\\", "/", -1)
	serviceImport := projectPath + "/" + servicePath

	handlerFile.Imports = []parser.NamedTypeValue{
		parser.NewNameType("httptransport", "\"github.com/go-kit/kit/transport/http\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/endpoint\""),
		parser.NewNameType("", "\""+endpointsImport+"\""),
		parser.NewNameType("", "\""+serviceImport+"\""),
	}

	// NewHTTPHandler
	{
		handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
			"NewHTTPHandler",
			`NewHTTPHandler returns a handler that makes a set of endpoints available on
			 predefined paths.`,
			parser.NamedTypeValue{},
			"m := http.NewServeMux()",
			[]parser.NamedTypeValue{
				parser.NewNameType("endpoints", "endpoints.Endpoints"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("", "http.Handler"),
			},
		))
		for _, m := range iface.Methods {
			handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
				fmt.Sprintf("DecodeHTTP%sRequest", m.Name),
				fmt.Sprintf(`DecodeHTTP%sRequest is a transport/http.DecodeRequestFunc that decodes a
					 JSON-encoded request from the HTTP request body. Primarily useful in a server.`,
					m.Name),
				parser.NamedTypeValue{},
				fmt.Sprintf(`var req endpoints.%sRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			return req,err`, m.Name),
				[]parser.NamedTypeValue{
					parser.NewNameType("_", "context.Context"),
					parser.NewNameType("r", "*http.Request"),
				},
				[]parser.NamedTypeValue{
					parser.NewNameType("", "interface{}"),
					parser.NewNameType("", "error"),
				},
			))
			handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
				fmt.Sprintf("EncodeHTTP%sResponse", m.Name),
				fmt.Sprintf(`EncodeHTTP%sResponse is a transport/http.EncodeResponseFunc that encodes
				the response as JSON to the response writer. Primarily useful in a server.`, m.Name),
				parser.NamedTypeValue{},
				` w.Header().Set("Content-Type", "application/json; charset=utf-8")
			err := json.NewEncoder(w).Encode(response)
			return err`,
				[]parser.NamedTypeValue{
					parser.NewNameType("_", "context.Context"),
					parser.NewNameType("w", "http.ResponseWriter"),
					parser.NewNameType("response", "interface{}"),
				},
				[]parser.NamedTypeValue{
					parser.NewNameType("", "error"),
				},
			))
			handlerFile.Methods[0].Body += "\n" + fmt.Sprintf(`m.Handle("/%s", httptransport.NewServer(
        endpoints.%sEndpoint,
        DecodeHTTP%sRequest,
        EncodeHTTP%sResponse,
    ))`, utils.ToLowerSnakeCase(m.Name), m.Name, m.Name, m.Name)
		}
		handlerFile.Methods[0].Body += "\n" + "return m"
	}

	// NewHTTPClient
	{
		handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
			"NewHTTPClient",
			`NewHTTPClient returns an AddService backed by an HTTP server living at the
			 remote instance. We expect instance to come from a service discovery system,
			 so likely of the form "host:port". We bake-in certain middlewares,
			 implementing the client library pattern.`,
			parser.NamedTypeValue{},
			`	// Quickly sanitize the instance string.
	if !strings.HasPrefix(instance, "http") {
		instance = "http://" + instance
	}
	u, err := url.Parse(instance)
	if err != nil {
		return nil, err
	}

	e := endpoints.Endpoints{}

	// Each individual endpoint is an http/transport.Client (which implements
	// endpoint.Endpoint) that gets wrapped with various middlewares. If you
	// made your own client library, you'd do this work there, so your server
	// could rely on a consistent set of client behavior.`,
			[]parser.NamedTypeValue{
				parser.NewNameType("instance", "string"),
			},
			[]parser.NamedTypeValue{
				//parser.NewNameType("", utils.ToUpperFirstCamelCase(fmt.Sprintf("service%s%sService", "",name))),
				parser.NewNameType("", fmt.Sprintf("service.%sService", utils.ToUpperFirstCamelCase(name))),
				parser.NewNameType("", "error"),
			},
		))

		handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
			"copyURL",
			"",
			parser.NamedTypeValue{},
			`	next := *base
	next.Path = path
	return &next`,
			[]parser.NamedTypeValue{
				parser.NewNameType("base", "*url.URL"),
				parser.NewNameType("path", "string"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("", "*url.URL"),
			},
		))

		for _, m := range iface.Methods {
			handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
				fmt.Sprintf("EncodeHTTP%sRequest", m.Name),
				fmt.Sprintf(`EncodeHTTP%sRequest is a transport/http.EncodeRequestFunc that
					 JSON-encodes any request to the request body. Primarily useful in a client.`,
					m.Name),
				parser.NamedTypeValue{},
				`	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(request); err != nil {
		return err
	}
	r.Body = ioutil.NopCloser(&buf)
	return nil`,
				[]parser.NamedTypeValue{
					parser.NewNameType("_", "context.Context"),
					parser.NewNameType("r", "*http.Request"),
					parser.NewNameType("request", "interface{}"),
				},
				[]parser.NamedTypeValue{
					parser.NewNameType("err", "error"),
				},
			))
			handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
				fmt.Sprintf("DecodeHTTP%sResponse", m.Name),
				fmt.Sprintf(`DecodeHTTP%sResponse is a transport/http.DecodeResponseFunc that decodes a
				JSON-encoded sum response from the HTTP response body. If the response has a
			    non-200 status code, we will interpret that as an error and attempt to decode
			    the specific error message from the response body. Primarily useful in a client.`, m.Name),
				parser.NamedTypeValue{},
				fmt.Sprintf(`	if r.StatusCode != http.StatusOK {
		return nil, errors.New(r.Status)
	}
	var resp endpoints.%sResponse
	err := json.NewDecoder(r.Body).Decode(&resp)
	return resp, err`, utils.ToUpperFirstCamelCase(m.Name)),
				[]parser.NamedTypeValue{
					parser.NewNameType("_", "context.Context"),
					parser.NewNameType("r", "*http.Response"),
				},
				[]parser.NamedTypeValue{
					parser.NewNameType("", "interface{}"),
					parser.NewNameType("", "error"),
				},
			))
			handlerFile.Methods[len(iface.Methods)*2+1].Body += "\n" + fmt.Sprintf(`// The %s endpoint is the same thing, with slightly different
	// middlewares to demonstrate how to specialize per-endpoint.
var %sEndpoint endpoint.Endpoint
{
	%sEndpoint = httptransport.NewClient(
		"POST",
		copyURL(u, "/%s"),
		EncodeHTTP%sRequest,
		DecodeHTTP%sResponse,
	).Endpoint()
}
e.%sEndpoint = %sEndpoint`, m.Name, utils.ToLowerFirstCamelCase(m.Name), utils.ToLowerFirstCamelCase(m.Name), strings.ToLower(m.Name), m.Name, m.Name, m.Name, utils.ToLowerFirstCamelCase(m.Name))
			handlerFile.Methods[len(iface.Methods)*2+1].Body += "\n"
		}
		handlerFile.Methods[len(iface.Methods)*2+1].Body += "\n" + `// Returning the endpoint.Set as a service.Service relies on the
	// endpoint.Set implementing the Service methods. That's just a simple bit
	// of glue code.
	return e, nil`
	}

	path, err := te.ExecuteString(viper.GetString("transport.path"), map[string]string{
		"ServiceName":   name,
		"TransportType": "http",
	})
	if err != nil {
		return err
	}
	b, err := defaultFs.Exists(path)
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("transport.file_name"), map[string]string{
		"ServiceName":   name,
		"TransportType": "http",
	})
	if err != nil {
		return err
	}
	tfile := path + defaultFs.FilePathSeparator() + fname
	if b {
		fex, err := defaultFs.Exists(tfile)
		if err != nil {
			return err
		}
		if fex {
			logrus.Errorf("Transport for service `%s` exist", name)
			logrus.Info("If you are trying to update a service use `gk update service [serviceName]`")
			return nil
		}
	} else {
		err = defaultFs.MkdirAll(path)
		if err != nil {
			return err
		}
	}
	return defaultFs.WriteFile(tfile, handlerFile.String(), false)
}
func (sg *ServiceInitGenerator) generateGRPCTransport(name string, iface *parser.Interface) error {
	logrus.Info("Generating grpc transport...")
	te := template.NewEngine()
	defaultFs := fs.Get()
	model := map[string]interface{}{
		"Name":    utils.ToUpperFirstCamelCase(name),
		"Methods": []map[string]string{},
	}
	mthds := []map[string]string{}
	for _, v := range iface.Methods {
		mthds = append(mthds, map[string]string{
			"Name":    v.Name,
			"Request": v.Name + "Request",
			"Reply":   v.Name + "Reply",
		})
	}
	model["Methods"] = mthds
	path, err := te.ExecuteString(viper.GetString("transport.path"), map[string]string{
		"ServiceName":   name,
		"TransportType": "grpc",
	})
	//path += defaultFs.FilePathSeparator() + "pb"
	path = "pb" + defaultFs.FilePathSeparator() + name

	if err != nil {
		return err
	}
	b, err := defaultFs.Exists(path)
	if err != nil {
		return err
	}
	fname := utils.ToLowerSnakeCase(name)
	//tfile := path + defaultFs.FilePathSeparator() + fname + ".proto"
	tfile := "pb" + defaultFs.FilePathSeparator() + name + defaultFs.FilePathSeparator() + fname + ".proto"
	if b {
		fex, err := defaultFs.Exists(tfile)
		if err != nil {
			return err
		}
		if fex {
			logrus.Errorf("Proto for service `%s` exist", name)
			return nil
		}
	} else {
		err = defaultFs.MkdirAll(path)
		if err != nil {
			return err
		}
	}
	protoTmpl, err := te.Execute("proto.pb", model)
	if err != nil {
		return err
	}
	err = defaultFs.WriteFile(tfile, protoTmpl, false)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		tfile := path + defaultFs.FilePathSeparator() + "compile.bat"
		cmpTmpl, err := te.Execute("proto_compile.bat", map[string]string{
			"Name": fname,
		})
		if err != nil {
			return err
		}
		logrus.Warn("--------------------------------------------------------------------")
		logrus.Warn("The service is still not ready!!")
		logrus.Warn("To create the grpc transport please create your protobuf.")
		logrus.Warn("Than follow the instructions in compile.bat and compile the .proto file.")
		logrus.Warnf("After the file is compiled run `gk init grpc %s`.", name)
		logrus.Warn("--------------------------------------------------------------------")
		return defaultFs.WriteFile(tfile, cmpTmpl, false)
	} else {
		tfile := path + defaultFs.FilePathSeparator() + "compile.sh"
		cmpTmpl, err := te.Execute("proto_compile.sh", map[string]string{
			"Name": fname,
		})
		if err != nil {
			return err
		}
		logrus.Warn("--------------------------------------------------------------------")
		logrus.Warn("The service is still not ready!!")
		logrus.Warn("To create the grpc transport please create your protobuf.")
		logrus.Warn("Than follow the instructions in compile.sh and compile the .proto file.")
		logrus.Warnf("After the file is compiled run `gk init grpc %s`.", name)
		logrus.Warn("--------------------------------------------------------------------")
		return defaultFs.WriteFile(tfile, cmpTmpl, false)
	}
}
func (sg *ServiceInitGenerator) generateThriftTransport(name string, iface *parser.Interface) error {
	logrus.Info("Generating thrift transport...")
	te := template.NewEngine()
	defaultFs := fs.Get()
	model := map[string]interface{}{
		"Name":    utils.ToUpperFirstCamelCase(name),
		"Methods": []map[string]string{},
	}
	mthds := []map[string]string{}
	for _, v := range iface.Methods {
		mthds = append(mthds, map[string]string{
			"Name":    v.Name,
			"Request": v.Name + "Request",
			"Reply":   v.Name + "Reply",
		})
	}
	model["Methods"] = mthds
	path, err := te.ExecuteString(viper.GetString("transport.path"), map[string]string{
		"ServiceName":   name,
		"TransportType": "thrift",
	})
	if err != nil {
		return err
	}
	b, err := defaultFs.Exists(path)
	if err != nil {
		return err
	}
	fname := utils.ToLowerSnakeCase(name)
	tfile := path + defaultFs.FilePathSeparator() + fname + ".thrift"
	if b {
		fex, err := defaultFs.Exists(tfile)
		if err != nil {
			return err
		}
		if fex {
			logrus.Errorf("Thrift for service `%s` exist", name)
			return nil
		}
	} else {
		err = defaultFs.MkdirAll(path)
		if err != nil {
			return err
		}
	}
	protoTmpl, err := te.Execute("svc.thrift", model)
	if err != nil {
		return err
	}
	err = defaultFs.WriteFile(tfile, protoTmpl, false)
	if err != nil {
		return err
	}

	var projectPath string
	goModPackage := utils.GetModPackage()
	if goModPackage == "" {
		gosrc := utils.GetGOPATH() + "/src/"
		gosrc = strings.Replace(gosrc, "\\", "/", -1)
		pwd, err := os.Getwd()
		if err != nil {
			return err
		}
		if viper.GetString("gk_folder") != "" {
			pwd += "/" + viper.GetString("gk_folder")
		}
		pwd = strings.Replace(pwd, "\\", "/", -1)
		projectPath = strings.Replace(pwd, gosrc, "", 1)
		if err != nil {
			return err
		}
	} else {
		projectPath = goModPackage
	}

	pkg := strings.Replace(path, "\\", "/", -1)
	pkg = projectPath + "/" + pkg
	if runtime.GOOS == "windows" {
		tfile := path + defaultFs.FilePathSeparator() + "compile.bat"
		cmpTmpl, err := te.Execute("thrift_compile.bat", map[string]string{
			"Name":    fname,
			"Package": pkg,
		})
		if err != nil {
			return err
		}
		logrus.Warn("--------------------------------------------------------------------")
		logrus.Warn("The service is still not ready!!")
		logrus.Warn("To create the thrift transport please create your thrift file.")
		logrus.Warn("Than follow the instructions in compile.bat and compile the .thrift file.")
		logrus.Warnf("After the file is compiled run `gk init thrift %s`.", name)
		logrus.Warn("--------------------------------------------------------------------")
		return defaultFs.WriteFile(tfile, cmpTmpl, false)
	} else {
		tfile := path + defaultFs.FilePathSeparator() + "compile.sh"
		cmpTmpl, err := te.Execute("thrift_compile.sh", map[string]string{
			"Name":    fname,
			"Package": pkg,
		})
		if err != nil {
			return err
		}
		logrus.Warn("--------------------------------------------------------------------")
		logrus.Warn("The service is still not ready!!")
		logrus.Warn("To create the thrift transport please create your thrift file.")
		logrus.Warn("Than follow the instructions in compile.sh and compile the .thrift file.")
		logrus.Warnf("After the file is compiled run `gk init thrift %s`.", name)
		logrus.Warn("--------------------------------------------------------------------")
		return defaultFs.WriteFile(tfile, cmpTmpl, false)
	}
}
func (sg *ServiceInitGenerator) generateEndpoints(name string, iface *parser.Interface) error {
	logrus.Info("Generating endpoints...")
	te := template.NewEngine()
	defaultFs := fs.Get()
	enpointsPath, err := te.ExecuteString(viper.GetString("endpoints.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	b, err := defaultFs.Exists(enpointsPath)
	if err != nil {
		return err
	}
	endpointsFileName, err := te.ExecuteString(viper.GetString("endpoints.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	eFile := enpointsPath + defaultFs.FilePathSeparator() + endpointsFileName
	if b {
		fex, err := defaultFs.Exists(eFile)
		if err != nil {
			return err
		}
		if fex {
			logrus.Errorf("Endpoints for service `%s` exist", name)
			logrus.Info("If you are trying to add functions to a service use `gk update service [serviceName]`")
			return nil
		}
	} else {
		err = defaultFs.MkdirAll(enpointsPath)
		if err != nil {
			return err
		}
	}
	file := parser.NewFile()
	file.Package = "endpoints"
	file.Structs = []parser.Struct{
		parser.NewStructWithComment(
			"Endpoints",
			fmt.Sprintf(`Endpoints collects all of the endpoints that compose the %s service. It's
				meant to be used as a helper struct, to collect all of the endpoints into a
				single parameter.`, name),
			[]parser.NamedTypeValue{}),
	}

	//
	var projectPath string
	goModPackage := utils.GetModPackage()
	if goModPackage == "" {
		gosrc := utils.GetGOPATH() + "/src/"
		gosrc = strings.Replace(gosrc, "\\", "/", -1)
		pwd, err := os.Getwd()
		if err != nil {
			return err
		}
		if viper.GetString("gk_folder") != "" {
			pwd += "/" + viper.GetString("gk_folder")
		}
		pwd = strings.Replace(pwd, "\\", "/", -1)
		projectPath = strings.Replace(pwd, gosrc, "", 1)
	} else {
		projectPath = goModPackage
	}

	servicePath, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	servicePath = strings.Replace(servicePath, "\\", "/", -1)
	serviceImport := projectPath + "/" + servicePath
	file.Imports = []parser.NamedTypeValue{
		parser.NewNameType("", "\"github.com/go-kit/kit/metrics\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/endpoint\""),
		//parser.NewNameType("logger", fmt.Sprintf(`"%s/pkg/logger"`, projectPath)),
		parser.NewNameType("", "\""+serviceImport+"\""),
	}
	file.Methods = []parser.Method{
		parser.NewMethodWithComment(
			"New",
			"New return a new instance of the endpoint that wraps the provided service.",
			parser.NamedTypeValue{},
			"",
			[]parser.NamedTypeValue{
				parser.NewNameType("svc", "service."+iface.Name),
				//parser.NewNameType("logger", "log.Logger"),
				//parser.NewNameType("duration", "metrics.Histogram"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("ep", "Endpoints"),
			},
		),
	}

	for i, v := range iface.Methods {
		file.Structs[0].Vars = append(file.Structs[0].Vars, parser.NewNameType(v.Name+"Endpoint", "endpoint.Endpoint"))
		reqPrams := []parser.NamedTypeValue{}
		for _, p := range v.Parameters {
			if p.Type != "context.Context" {
				n := strings.ToUpper(string(p.Name[0])) + p.Name[1:]
				reqPrams = append(reqPrams, parser.NewNameType(n, p.Type))
			}
		}
		resultPrams := []parser.NamedTypeValue{}
		for _, p := range v.Results {
			n := strings.ToUpper(string(p.Name[0])) + p.Name[1:]
			resultPrams = append(resultPrams, parser.NewNameType(n, p.Type))
		}
		req := parser.NewStructWithComment(
			v.Name+"Request",
			fmt.Sprintf(
				"%sRequest collects the request parameters for the %s method.",
				v.Name, v.Name,
			),
			reqPrams,
		)
		res := parser.NewStructWithComment(
			v.Name+"Response",
			fmt.Sprintf(
				"%sResponse collects the response values for the %s method.",
				v.Name, v.Name,
			),
			resultPrams,
		)
		file.Structs = append(file.Structs, req)
		file.Structs = append(file.Structs, res)
		tmplModel := map[string]interface{}{
			"Calling":  v,
			"Request":  req,
			"Response": res,
		}
		tRes, err := te.ExecuteString("{{template \"endpoint_func\" .}}", tmplModel)
		if err != nil {
			return err
		}
		file.Methods = append(file.Methods, parser.NewMethodWithComment(
			"Make"+v.Name+"Endpoint",
			fmt.Sprintf(`Make%sEndpoint returns an endpoint that invokes %s on the service.
				  Primarily useful in a server.`, v.Name, v.Name),
			parser.NamedTypeValue{},
			tRes,
			[]parser.NamedTypeValue{
				parser.NewNameType("svc", "service."+iface.Name),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("ep", "endpoint.Endpoint"),
			},
		))

		tRes, err = te.ExecuteString("{{template \"endpoint_method_func\" .}}", tmplModel)
		if err != nil {
			return err
		}
		file.Methods = append(file.Methods, parser.NewMethodWithComment(
			v.Name,
			fmt.Sprintf(`%s implements the service interface, so Endpoints may be used as a service.
					  This is primarily useful in the context of a client library.`, v.Name),
			parser.NewNameType("e", "Endpoints"),
			tRes,
			v.Parameters,
			v.Results,
		))

		//
		tn := utils.ToLowerFirstCamelCase(file.Structs[0].Vars[i].Name)
		buf := []string{
			fmt.Sprintf("var %s endpoint.Endpoint", tn),
			"{",
			fmt.Sprintf("%s = Make%sEndpoint(svc)", tn, v.Name),
			//fmt.Sprintf(`%s = LoggingMiddleware(log.With(logger, "method", "%s"))(%s)`, tn, v.Name, tn),
			//fmt.Sprintf(`%s = InstrumentingMiddleware(duration.With("method", "%s"))(%s)`, tn, v.Name, tn),
			"}",
			fmt.Sprintf(`ep.%s = %s`, file.Structs[0].Vars[i].Name, tn),
		}

		file.Methods[0].Body += "\n" + strings.Join(buf, "\n")
	}
	file.Methods[0].Body += "\n return ep"
	return defaultFs.WriteFile(eFile, file.String(), false)
}

func NewServiceInitGenerator() *ServiceInitGenerator {
	return &ServiceInitGenerator{}
}

type ServicePatchGenerator struct{}

func (sg *ServicePatchGenerator) Generator(name string) error {
	logrus.Info("Patching service middleware...")
	te := template.NewEngine()
	defaultFs := fs.Get()

	path, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	mname, err := te.ExecuteString(viper.GetString("middleware.name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	iname, err := te.ExecuteString(viper.GetString("service.interface_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	sfile := path + defaultFs.FilePathSeparator() + fname
	b, err := defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Service %s was not found", name))
	}
	//middleware
	mfile := path + defaultFs.FilePathSeparator() + mname
	b, err = defaultFs.Exists(mfile)
	if err != nil {
		return err
	}
	if !b {
		logrus.Errorf("Middleware for service `%s` not exist", name)
		logrus.Info("If you are trying to patch a service for middleware. Please execute `gk new middleware service [serviceName]` first.")
		return err
	}
	p := parser.NewFileParser()
	s, err := defaultFs.ReadFile(sfile)
	if err != nil {
		return err
	}
	f, err := p.Parse([]byte(s))
	if err != nil {
		return err
	}
	var iface *parser.Interface
	for _, v := range f.Interfaces {
		if v.Name == iname {
			iface = &v
		}
	}
	if iface == nil {
		return errors.New(fmt.Sprintf("Could not find the service interface in `%s`", sfile))
	}
	toKeep := []parser.Method{}
	for _, v := range iface.Methods {
		isOk := false
		for _, p := range v.Parameters {
			if p.Type == "context.Context" {
				isOk = true
				break
			}
		}
		if string(v.Name[0]) == strings.ToLower(string(v.Name[0])) {
			logrus.Warnf("The method '%s' is private and will be ignored", v.Name)
			continue
		}
		if len(v.Results) == 0 {
			logrus.Warnf("The method '%s' does not have any return value and will be ignored", v.Name)
			continue
		}
		if !isOk {
			logrus.Warnf("The method '%s' does not have a context and will be ignored", v.Name)
		}
		if isOk {
			toKeep = append(toKeep, v)
		}

	}
	iface.Methods = toKeep
	if len(iface.Methods) == 0 {
		return errors.New("The service has no suitable methods please implement the interface methods")
	}

	stubName, err := te.ExecuteString(viper.GetString("service.struct_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	// patch new
	buf := f.Methods[1]
	// reset
	buf.Parameters = []parser.NamedTypeValue{}
	ms := []string{}
	for _, v := range iface.Methods {
		ms = append(ms, strings.ToLower(v.Name))
		buf.Parameters = append(buf.Parameters, parser.NewNameType(strings.ToLower(v.Name), "metrics.Counter"))
	}
	buf.Parameters = append([]parser.NamedTypeValue{
		parser.NewNameType("logger", "log.Logger"),
	}, buf.Parameters...)

	body := []string{
		fmt.Sprintf("var svc %s", iname),
		"{",
		fmt.Sprintf("svc = &%s{}", stubName),
		"svc = LoggingMiddleware(logger)(svc)",
		fmt.Sprintf("svc = InstrumentingMiddleware(%s)(svc)", strings.Join(ms, ",")),
		"}",
		"return svc",
	}
	f.Methods[1] = parser.NewMethodWithComment(
		buf.Name,
		strings.TrimSuffix(strings.Replace(buf.Comment, "/", "", -1), "\n"),
		buf.Struct,
		strings.Join(body, "\n"),
		buf.Parameters,
		buf.Results,
	)

	f.Imports = append(f.Imports, []parser.NamedTypeValue{
		parser.NewNameType("", "\"github.com/go-kit/kit/log\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/metrics\""),
	}...)

	err = defaultFs.WriteFile(sfile, f.String(), true)
	if err != nil {
		return err
	}

	err = sg.generatePathEndpoints(name, iface)
	if err != nil {
		return err
	}

	return nil
}

func (sg *ServicePatchGenerator) generatePathEndpoints(name string, iface *parser.Interface) error {
	logrus.Info("Patching endpoints middleware...")
	te := template.NewEngine()
	defaultFs := fs.Get()

	path, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	mname, err := te.ExecuteString(viper.GetString("middleware.name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	epath, err := te.ExecuteString(viper.GetString("endpoints.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	ename, err := te.ExecuteString(viper.GetString("endpoints.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	// server/service.go
	sfile := path + defaultFs.FilePathSeparator() + fname
	b, err := defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Service %s was not found", name))
	}
	// endpoints/endpoint.go
	efile := epath + defaultFs.FilePathSeparator() + ename
	b, err = defaultFs.Exists(efile)
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Endpoint %s was not found", name))
	}
	// endpoints/middleware.go
	mfile := epath + defaultFs.FilePathSeparator() + mname
	b, err = defaultFs.Exists(mfile)
	if err != nil {
		return err
	}
	if !b {
		logrus.Errorf("Middleware for endpoints `%s` not exist", name)
		logrus.Info("If you are trying to patch a endpoints for middleware. Please execute `gk new middleware service [serviceName]` first.")
		return err
	}
	p := parser.NewFileParser()
	s, err := defaultFs.ReadFile(efile)
	if err != nil {
		return err
	}
	f, err := p.Parse([]byte(s))
	if err != nil {
		return err
	}

	// patch
	buf := f.Methods[0]
	// reset
	buf.Parameters = []parser.NamedTypeValue{
		parser.NewNameType("svc", "service."+iface.Name),
		parser.NewNameType("logger", "log.Logger"),
		parser.NewNameType("duration", "metrics.Histogram"),
	}
	buf.Body = ""

	for _, v := range iface.Methods {
		tn := fmt.Sprintf("%sEndpoint", utils.ToLowerFirstCamelCase(v.Name))
		body := []string{
			fmt.Sprintf("var %s endpoint.Endpoint", tn),
			"{",
			fmt.Sprintf("%s = Make%sEndpoint(svc)", tn, v.Name),
			fmt.Sprintf(`%s = LoggingMiddleware(log.With(logger, "method", "%s"))(%s)`, tn, v.Name, tn),
			fmt.Sprintf(`%s = InstrumentingMiddleware(duration.With("method", "%s"))(%s)`, tn, v.Name, tn),
			"}",
			fmt.Sprintf(`ep.%sEndpoint = %s`, utils.ToUpperFirstCamelCase(v.Name), tn),
		}
		buf.Body += "\n" + strings.Join(body, "\n")
	}
	buf.Body += "\n" + "return ep"

	f.Methods[0] = buf
	f.Imports = append(f.Imports, []parser.NamedTypeValue{
		parser.NewNameType("", "\"github.com/go-kit/kit/log\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/metrics\""),
	}...)
	err = defaultFs.WriteFile(efile, f.String(), true)
	if err != nil {
		return err
	}

	return nil
}

func NewServicePatchGenerator() *ServicePatchGenerator {
	return &ServicePatchGenerator{}
}

type GRPCInitGenerator struct {
}

func (sg *GRPCInitGenerator) Generate(name string) error {
	te := template.NewEngine()
	defaultFs := fs.Get()
	path, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	sfile := path + defaultFs.FilePathSeparator() + fname
	b, err := defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	iname, err := te.ExecuteString(viper.GetString("service.interface_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Service %s was not found", name))
	}
	p := parser.NewFileParser()
	s, err := defaultFs.ReadFile(sfile)
	if err != nil {
		return err
	}
	f, err := p.Parse([]byte(s))
	if err != nil {
		return err
	}
	var iface *parser.Interface
	for _, v := range f.Interfaces {
		if v.Name == iname {
			iface = &v
		}
	}
	if iface == nil {
		return errors.New(fmt.Sprintf("Could not find the service interface in `%s`", sfile))
	}
	toKeep := []parser.Method{}
	for _, v := range iface.Methods {
		isOk := false
		for _, p := range v.Parameters {
			if p.Type == "context.Context" {
				isOk = true
				break
			}
		}
		if string(v.Name[0]) == strings.ToLower(string(v.Name[0])) {
			logrus.Warnf("The method '%s' is private and will be ignored", v.Name)
			continue
		}
		if len(v.Results) == 0 {
			logrus.Warnf("The method '%s' does not have any return value and will be ignored", v.Name)
			continue
		}
		if !isOk {
			logrus.Warnf("The method '%s' does not have a context and will be ignored", v.Name)
		}
		if isOk {
			toKeep = append(toKeep, v)
		}

	}
	iface.Methods = toKeep
	if len(iface.Methods) == 0 {
		return errors.New("The service has no method please implement the interface methods")
	}
	path, err = te.ExecuteString(viper.GetString("transport.path"), map[string]string{
		"ServiceName":   name,
		"TransportType": "grpc",
	})
	if err != nil {
		return err
	}
	//sfile = path + defaultFs.FilePathSeparator() + "pb" + defaultFs.FilePathSeparator() + utils.ToLowerSnakeCase(name) + ".pb.go"
	sfile = "pb" + defaultFs.FilePathSeparator() + utils.ToLowerSnakeCase(name) + defaultFs.FilePathSeparator() + utils.ToLowerSnakeCase(name) + ".pb.go"
	b, err = defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	if !b {
		return errors.New("Could not find the compiled pb of the service")
	}

	//
	var projectPath string
	goModPackage := utils.GetModPackage()
	if goModPackage == "" {
		gosrc := utils.GetGOPATH() + "/src/"
		gosrc = strings.Replace(gosrc, "\\", "/", -1)
		pwd, err := os.Getwd()
		if err != nil {
			return err
		}
		if viper.GetString("gk_folder") != "" {
			pwd += "/" + viper.GetString("gk_folder")
		}
		pwd = strings.Replace(pwd, "\\", "/", -1)
		projectPath = strings.Replace(pwd, gosrc, "", 1)
	} else {
		projectPath = goModPackage
	}

	//pbImport := projectPath + "/" + path + defaultFs.FilePathSeparator() + "pb"
	pbImport := projectPath + defaultFs.FilePathSeparator() + "pb" + defaultFs.FilePathSeparator() + utils.ToLowerSnakeCase(name)
	pbImport = strings.Replace(pbImport, "\\", "/", -1)
	enpointsPath, err := te.ExecuteString(viper.GetString("endpoints.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	enpointsPath = strings.Replace(enpointsPath, "\\", "/", -1)
	endpointsImport := projectPath + "/" + enpointsPath

	servicePath, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	servicePath = strings.Replace(servicePath, "\\", "/", -1)
	serviceImport := projectPath + "/" + servicePath

	handler := parser.NewFile()
	handler.Package = "transports"
	handler.Imports = []parser.NamedTypeValue{
		parser.NewNameType("oldcontext", "\"golang.org/x/net/context\""),
		parser.NewNameType("", "\"context\""),
		parser.NewNameType("", "\"errors\""),
		parser.NewNameType("", "\"google.golang.org/grpc\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/endpoint\""),
		parser.NewNameType("", fmt.Sprintf("\"%s\"", pbImport)),
		parser.NewNameType("", fmt.Sprintf("\"%s\"", endpointsImport)),
		parser.NewNameType("", fmt.Sprintf("\"%s\"", serviceImport)),
		parser.NewNameType("grpctransport", "\"github.com/go-kit/kit/transport/grpc\""),
	}
	grpcStruct := parser.NewStruct("grpcServer", []parser.NamedTypeValue{})

	// NewGRPCServer
	{
		handler.Methods = append(handler.Methods, parser.NewMethodWithComment(
			"MakeGRPCServer",
			`MakeGRPCServer makes a set of endpoints available as a gRPC server.`,
			parser.NamedTypeValue{},
			`req = &grpcServer{`,
			[]parser.NamedTypeValue{
				parser.NewNameType("endpoints", "endpoints.Endpoints"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("req", fmt.Sprintf("pb.%sServer", utils.ToUpperFirstCamelCase(name))),
			},
		))
		for _, v := range iface.Methods {
			grpcStruct.Vars = append(grpcStruct.Vars, parser.NewNameType(
				utils.ToLowerFirstCamelCase(v.Name),
				"grpctransport.Handler",
			))

			// DecodeGRPC Request
			{
				reqPrams := []parser.NamedTypeValue{}
				resultPrams := []parser.NamedTypeValue{}
				for _, p := range v.Parameters {
					if p.Type != "context.Context" {
						n := strings.ToUpper(string(p.Name[0])) + p.Name[1:]
						reqPrams = append(reqPrams, parser.NewNameType(n, p.Type))
						resultPrams = append(resultPrams, parser.NewNameType(n, p.Type))
					}
				}
				req := parser.NewStructWithComment(
					fmt.Sprintf("*pb.%sRequest", v.Name),
					fmt.Sprintf(
						"endpoints.%sRequest collects the request parameters for the %s method.",
						v.Name, v.Name,
					),
					reqPrams,
				)
				res := parser.NewStructWithComment(
					fmt.Sprintf("endpoints.%sRequest", v.Name),
					fmt.Sprintf(
						"&pb.%sRequest collects the response values for the %s method.",
						v.Name, v.Name,
					),
					resultPrams,
				)
				tmplModel := map[string]interface{}{
					"Calling":  v,
					"Request":  req,
					"Response": res,
				}
				tRes, err := te.ExecuteString("{{template \"transport_grpc_server_decode_func\" .}}", tmplModel)
				if err != nil {
					return err
				}
				handler.Methods = append(handler.Methods, parser.NewMethodWithComment(
					"DecodeGRPC"+v.Name+"Request",
					fmt.Sprintf(
						`DecodeGRPC%sRequest is a transport/grpc.DecodeRequestFunc that converts a
				gRPC request to a user-domain request. Primarily useful in a server.`,
						v.Name,
					),
					parser.NamedTypeValue{},
					tRes,
					[]parser.NamedTypeValue{
						parser.NewNameType("_", "context.Context"),
						parser.NewNameType("grpcReq", "interface{}"),
					},
					[]parser.NamedTypeValue{
						parser.NewNameType("", "interface{}"),
						parser.NewNameType("", "error"),
					},
				))
			}

			// EncodeGRPC Response
			{
				reqPrams := []parser.NamedTypeValue{}
				resultPrams := []parser.NamedTypeValue{}
				for _, p := range v.Results {
					if p.Type != "context.Context" {
						n := strings.ToUpper(string(p.Name[0])) + p.Name[1:]
						reqPrams = append(reqPrams, parser.NewNameType(n, p.Type))
						resultPrams = append(resultPrams, parser.NewNameType(n, p.Type))
					}
				}
				req := parser.NewStructWithComment(
					fmt.Sprintf("endpoints.%sResponse", v.Name),
					fmt.Sprintf(
						"endpoints.%sResponse collects the response values for the %s method.",
						v.Name, v.Name,
					),
					resultPrams,
				)
				res := parser.NewStructWithComment(
					fmt.Sprintf("&pb.%sReply", v.Name),
					fmt.Sprintf(
						"&pb.%sReply collects the request parameters for the %s method.",
						v.Name, v.Name,
					),
					reqPrams,
				)
				tmplModel := map[string]interface{}{
					"Calling":  v,
					"Request":  req,
					"Response": res,
				}
				tRes, err := te.ExecuteString("{{template \"transport_grpc_server_encode_func\" .}}", tmplModel)
				if err != nil {
					return err
				}
				handler.Methods = append(handler.Methods, parser.NewMethodWithComment(
					"EncodeGRPC"+v.Name+"Response",
					fmt.Sprintf(
						`EncodeGRPC%sResponse is a transport/grpc.EncodeResponseFunc that converts a
					user-domain response to a gRPC reply. Primarily useful in a server.`,
						v.Name,
					),
					parser.NamedTypeValue{},
					tRes,
					[]parser.NamedTypeValue{
						parser.NewNameType("_", "context.Context"),
						parser.NewNameType("grpcReply", "interface{}"),
					},
					[]parser.NamedTypeValue{
						parser.NewNameType("res", "interface{}"),
						parser.NewNameType("err", "error"),
					},
				))
			}

			handler.Methods = append(handler.Methods, parser.NewMethod(
				v.Name,
				parser.NewNameType("s", "*grpcServer"),
				fmt.Sprintf(
					`_, rp, err := s.%s.ServeGRPC(ctx, req)
					if err != nil {
						return nil, err
					}
					rep = rp.(*pb.%sReply)
					return rep, err`,
					utils.ToLowerFirstCamelCase(v.Name),
					v.Name,
				),
				[]parser.NamedTypeValue{
					parser.NewNameType("ctx", "oldcontext.Context"),
					parser.NewNameType("req", fmt.Sprintf("*pb.%sRequest", v.Name)),
				},
				[]parser.NamedTypeValue{
					parser.NewNameType("rep", fmt.Sprintf("*pb.%sReply", v.Name)),
					parser.NewNameType("err", "error"),
				},
			))
			handler.Methods[0].Body += "\n" + fmt.Sprintf(`%s : grpctransport.NewServer(
			endpoints.%sEndpoint,
			DecodeGRPC%sRequest,
			EncodeGRPC%sResponse,
		),
		`, utils.ToLowerFirstCamelCase(v.Name), v.Name, v.Name, v.Name)
		}
		handler.Methods[0].Body += `}
	return req`
	}

	// NewGRPCClient
	{
		handler.Methods = append(handler.Methods, parser.NewMethodWithComment(
			"NewGRPCClient",
			`NewGRPCClient returns an AddService backed by a gRPC server at the other end
						of the conn. The caller is responsible for constructing the conn, and
						eventually closing the underlying transport. We bake-in certain middlewares,
						implementing the client library pattern.`,
			parser.NamedTypeValue{},
			`e := endpoints.Endpoints{}`,
			[]parser.NamedTypeValue{
				parser.NewNameType("conn", "*grpc.ClientConn"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("", fmt.Sprintf("service.%sService", utils.ToUpperFirstCamelCase(name))),
			},
		))

		for _, v := range iface.Methods {
			// EncodeGRPC Request
			{
				reqPrams := []parser.NamedTypeValue{}
				resultPrams := []parser.NamedTypeValue{}
				for _, p := range v.Parameters {
					if p.Type != "context.Context" {
						n := strings.ToUpper(string(p.Name[0])) + p.Name[1:]
						reqPrams = append(reqPrams, parser.NewNameType(n, p.Type))
						resultPrams = append(resultPrams, parser.NewNameType(n, p.Type))
					}
				}
				req := parser.NewStructWithComment(
					fmt.Sprintf("endpoints.%sRequest", v.Name),
					fmt.Sprintf(
						"endpoints.%sRequest collects the request parameters for the %s method.",
						v.Name, v.Name,
					),
					reqPrams,
				)
				res := parser.NewStructWithComment(
					fmt.Sprintf("&pb.%sRequest", v.Name),
					fmt.Sprintf(
						"&pb.%sRequest collects the response values for the %s method.",
						v.Name, v.Name,
					),
					resultPrams,
				)
				tmplModel := map[string]interface{}{
					"Calling":  v,
					"Request":  req,
					"Response": res,
				}
				tRes, err := te.ExecuteString("{{template \"transport_grpc_client_encode_func\" .}}", tmplModel)
				if err != nil {
					return err
				}
				handler.Methods = append(handler.Methods, parser.NewMethodWithComment(
					"EncodeGRPC"+v.Name+"Request",
					fmt.Sprintf(
						`EncodeGRPC%sRequest is a transport/grpc.EncodeRequestFunc that converts a
					user-domain %s request to a gRPC %s request. Primarily useful in a client.`,
						v.Name, v.Name, v.Name,
					),
					parser.NamedTypeValue{},
					tRes,
					[]parser.NamedTypeValue{
						parser.NewNameType("_", "context.Context"),
						parser.NewNameType("request", "interface{}"),
					},
					[]parser.NamedTypeValue{
						parser.NewNameType("", "interface{}"),
						parser.NewNameType("", "error"),
					},
				))
			}

			{
				reqPrams := []parser.NamedTypeValue{}
				resultPrams := []parser.NamedTypeValue{}
				for _, p := range v.Results {
					if p.Type != "context.Context" {
						n := strings.ToUpper(string(p.Name[0])) + p.Name[1:]
						reqPrams = append(reqPrams, parser.NewNameType(n, p.Type))
						resultPrams = append(resultPrams, parser.NewNameType(n, p.Type))
					}
				}
				req := parser.NewStructWithComment(
					fmt.Sprintf("*pb.%sReply", v.Name),
					fmt.Sprintf(
						"*pb.%sReply collects the request parameters for the %s method.",
						v.Name, v.Name,
					),
					reqPrams,
				)
				res := parser.NewStructWithComment(
					fmt.Sprintf("endpoints.%sResponse", v.Name),
					fmt.Sprintf(
						"endpoints.%sResponse collects the response values for the %s method.",
						v.Name, v.Name,
					),
					resultPrams,
				)
				tmplModel := map[string]interface{}{
					"Calling":  v,
					"Request":  req,
					"Response": res,
				}
				tRes, err := te.ExecuteString("{{template \"transport_grpc_client_decode_func\" .}}", tmplModel)
				if err != nil {
					return err
				}
				handler.Methods = append(handler.Methods, parser.NewMethodWithComment(
					"DecodeGRPC"+v.Name+"Response",
					fmt.Sprintf(
						`DecodeGRPC%sResponse is a transport/grpc.DecodeResponseFunc that converts a
					gRPC %s reply to a user-domain %s response. Primarily useful in a client.`,
						v.Name, v.Name, v.Name,
					),
					parser.NamedTypeValue{},
					tRes,
					[]parser.NamedTypeValue{
						parser.NewNameType("_", "context.Context"),
						parser.NewNameType("grpcReply", "interface{}"),
					},
					[]parser.NamedTypeValue{
						parser.NewNameType("", "interface{}"),
						parser.NewNameType("", "error"),
					},
				))
			}

			handler.Methods[len(iface.Methods)*3+1].Body += "\n\n" + fmt.Sprintf(`// The %s endpoint is the same thing, with slightly different
	// middlewares to demonstrate how to specialize per-endpoint.
				var %sEndpoint endpoint.Endpoint
				{
					%sEndpoint = grpctransport.NewClient(
						conn,
						"pb.%s",
						"%s",
						EncodeGRPC%sRequest,
						DecodeGRPC%sResponse,
						pb.%sReply{},
					).Endpoint()
				}
				e.%sEndpoint = %sEndpoint`, v.Name, utils.ToLowerFirstCamelCase(v.Name), utils.ToLowerFirstCamelCase(v.Name), utils.ToUpperFirstCamelCase(name),
				v.Name, v.Name, v.Name, v.Name, v.Name, utils.ToLowerFirstCamelCase(v.Name))
		}
		handler.Methods[len(iface.Methods)*3+1].Body += "\n\n" + `return e`
	}

	// annoying helper functions
	{
		handler.Methods = append(handler.Methods, parser.NewMethodWithComment(
			"str2err",
			"",
			parser.NamedTypeValue{},
			`if s == "" {
						return nil
					}
					return errors.New(s)`,
			[]parser.NamedTypeValue{
				parser.NewNameType("s", "string"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("", "error"),
			},
		))

		handler.Methods = append(handler.Methods, parser.NewMethodWithComment(
			"err2str",
			"",
			parser.NamedTypeValue{},
			`	if err == nil {
					return ""
				}
				return err.Error()`,
			[]parser.NamedTypeValue{
				parser.NewNameType("err", "error"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("", "string"),
			},
		))
	}

	handler.Structs = append(handler.Structs, grpcStruct)
	fname, err = te.ExecuteString(viper.GetString("transport.file_name"), map[string]string{
		"ServiceName":   name,
		"TransportType": "grpc",
	})
	if err != nil {
		return err
	}
	sfile = path + defaultFs.FilePathSeparator() + fname
	err = defaultFs.WriteFile(sfile, handler.String(), false)
	if err != nil {
		return err
	}
	logrus.Warn("---------------------------------------------------------------------------------------")
	logrus.Warn("The generator does not implement the Decoding and Encoding of the grpc request/response")
	logrus.Warn("Before using the service don't forget to implement those.")
	logrus.Warn("---------------------------------------------------------------------------------------")
	return nil
}

func NewGRPCInitGenerator() *GRPCInitGenerator {
	return &GRPCInitGenerator{}
}

type ThriftInitGenerator struct {
}

func (sg *ThriftInitGenerator) Generate(name string) error {
	te := template.NewEngine()
	defaultFs := fs.Get()
	path, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	sfile := path + defaultFs.FilePathSeparator() + fname
	b, err := defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	iname, err := te.ExecuteString(viper.GetString("service.interface_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Service %s was not found", name))
	}
	p := parser.NewFileParser()
	s, err := defaultFs.ReadFile(sfile)
	if err != nil {
		return err
	}
	f, err := p.Parse([]byte(s))
	if err != nil {
		return err
	}
	var iface *parser.Interface
	for _, v := range f.Interfaces {
		if v.Name == iname {
			iface = &v
		}
	}
	if iface == nil {
		return errors.New(fmt.Sprintf("Could not find the service interface in `%s`", sfile))
	}
	toKeep := []parser.Method{}
	for _, v := range iface.Methods {
		isOk := false
		for _, p := range v.Parameters {
			if p.Type == "context.Context" {
				isOk = true
				break
			}
		}
		if string(v.Name[0]) == strings.ToLower(string(v.Name[0])) {
			logrus.Warnf("The method '%s' is private and will be ignored", v.Name)
			continue
		}
		if len(v.Results) == 0 {
			logrus.Warnf("The method '%s' does not have any return value and will be ignored", v.Name)
			continue
		}
		if !isOk {
			logrus.Warnf("The method '%s' does not have a context and will be ignored", v.Name)
		}
		if isOk {
			toKeep = append(toKeep, v)
		}

	}
	iface.Methods = toKeep
	if len(iface.Methods) == 0 {
		return errors.New("The service has no method please implement the interface methods")
	}
	path, err = te.ExecuteString(viper.GetString("transport.path"), map[string]string{
		"ServiceName":   name,
		"TransportType": "thrift",
	})
	if err != nil {
		return err
	}
	sfile = path + defaultFs.FilePathSeparator() + "gen-go" + defaultFs.FilePathSeparator() +
		utils.ToLowerSnakeCase(name) + defaultFs.FilePathSeparator() +
		utils.ToLowerSnakeCase(name) + ".go"
	b, err = defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	if !b {
		return errors.New("Could not find the compiled thrift of the service")
	}
	gosrc := utils.GetGOPATH() + "/src/"
	gosrc = strings.Replace(gosrc, "\\", "/", -1)
	pwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if viper.GetString("gk_folder") != "" {
		pwd += "/" + viper.GetString("gk_folder")
	}
	pwd = strings.Replace(pwd, "\\", "/", -1)
	projectPath := strings.Replace(pwd, gosrc, "", 1)
	thriftImport := projectPath + "/" + path + "/" + "gen-go" +
		"/" + utils.ToLowerSnakeCase(name)
	thriftImport = strings.Replace(thriftImport, "\\", "/", -1)
	enpointsPath, err := te.ExecuteString(viper.GetString("endpoints.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	enpointsPath = strings.Replace(enpointsPath, "\\", "/", -1)
	endpointsImport := projectPath + "/" + enpointsPath
	handler := parser.NewFile()
	handler.Package = "thrift"
	handler.Imports = []parser.NamedTypeValue{
		parser.NewNameType("", "\"context\""),
		parser.NewNameType("", "\"errors\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/endpoint\""),
		parser.NewNameType(
			fmt.Sprintf("thrift%s", utils.ToUpperFirstCamelCase(name)),
			fmt.Sprintf("\"%s\"", thriftImport),
		),
		parser.NewNameType("", fmt.Sprintf("\"%s\"", endpointsImport)),
	}
	thriftStruct := parser.NewStruct("thriftServer", []parser.NamedTypeValue{
		parser.NewNameType("ctx", "context.Context"),
	})
	handler.Methods = append(handler.Methods, parser.NewMethodWithComment(
		"MakeThriftHandler",
		`MakeThriftHandler makes a set of endpoints available as a thrift server.`,
		parser.NamedTypeValue{},
		`req = &thriftServer{
				ctx:    ctx,`,
		[]parser.NamedTypeValue{
			parser.NewNameType("ctx", "context.Context"),
			parser.NewNameType("endpoints", "endpoints.Endpoints"),
		},
		[]parser.NamedTypeValue{
			parser.NewNameType("req", fmt.Sprintf("thrift%s.%sService",
				utils.ToUpperFirstCamelCase(name), utils.ToUpperFirstCamelCase(name))),
		},
	))
	for _, v := range iface.Methods {
		thriftStruct.Vars = append(thriftStruct.Vars, parser.NewNameType(
			utils.ToLowerFirstCamelCase(v.Name),
			"endpoint.Endpoint",
		))
		handler.Methods = append(handler.Methods, parser.NewMethodWithComment(
			"DecodeThrift"+v.Name+"Request",
			fmt.Sprintf(
				`DecodeThrift%sRequest is a func that converts a
				thrift request to a user-domain request. Primarily useful in a server.
				TODO: Do not forget to implement the decoder.`,
				v.Name,
			),
			parser.NamedTypeValue{},
			fmt.Sprintf(`err = errors.New("'%s' Decoder is not impelement")
			return req, err`, v.Name),
			[]parser.NamedTypeValue{
				parser.NewNameType("r", fmt.Sprintf("*thrift%s.%sRequest",
					utils.ToUpperFirstCamelCase(name), utils.ToUpperFirstCamelCase(v.Name))),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("req", fmt.Sprintf("endpoints.%sRequest",
					utils.ToUpperFirstCamelCase(v.Name))),
				parser.NewNameType("err", "error"),
			},
		))
		handler.Methods = append(handler.Methods, parser.NewMethodWithComment(
			"EncodeThrift"+v.Name+"Response",
			fmt.Sprintf(
				`EncodeThrift%sResponse is a func that converts a
					user-domain response to a thrift reply. Primarily useful in a server.
					TODO: Do not forget to implement the encoder.`,
				v.Name,
			),
			parser.NamedTypeValue{},
			fmt.Sprintf(`err = errors.New("'%s' Encoder is not impelement")
			return rep, err`, v.Name),
			[]parser.NamedTypeValue{
				parser.NewNameType("reply", "interface{}"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("rep", fmt.Sprintf("thrift%s.%sReply",
					utils.ToUpperFirstCamelCase(name), utils.ToUpperFirstCamelCase(v.Name))),
				parser.NewNameType("err", "error"),
			},
		))
		handler.Methods = append(handler.Methods, parser.NewMethod(
			v.Name,
			parser.NewNameType("s", "*thriftServer"),
			fmt.Sprintf(
				`request,err:=DecodeThrift%sRequest(req)
					if err != nil {
						return nil, err
					}
					response, err := s.%s(s.ctx, request)
					if err != nil {
						return nil, err
					}
					r,err := EncodeThrift%sResponse(response)
					rep = &r
					return rep, err`,
				utils.ToUpperFirstCamelCase(v.Name),
				utils.ToLowerFirstCamelCase(v.Name),
				utils.ToUpperFirstCamelCase(v.Name),
			),
			[]parser.NamedTypeValue{
				parser.NewNameType("req", fmt.Sprintf("*thrift%s.%sRequest", utils.ToUpperFirstCamelCase(name), utils.ToUpperFirstCamelCase(v.Name))),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("rep", fmt.Sprintf("*thrift%s.%sReply", utils.ToUpperFirstCamelCase(name), utils.ToUpperFirstCamelCase(v.Name))),
				parser.NewNameType("err", "error"),
			},
		))
		handler.Methods[0].Body += "\n" + fmt.Sprintf(`%s :  endpoints.%sEndpoint,`,
			utils.ToLowerFirstCamelCase(v.Name), utils.ToUpperFirstCamelCase(v.Name))
	}
	handler.Methods[0].Body += `
	}
	return req`
	handler.Structs = append(handler.Structs, thriftStruct)
	fname, err = te.ExecuteString(viper.GetString("transport.file_name"), map[string]string{
		"ServiceName":   name,
		"TransportType": "thrift",
	})
	if err != nil {
		return err
	}
	sfile = path + defaultFs.FilePathSeparator() + fname
	err = defaultFs.WriteFile(sfile, handler.String(), false)
	if err != nil {
		return err
	}
	logrus.Warn("---------------------------------------------------------------------------------------")
	logrus.Warn("The generator does not implement the Decoding and Encoding of the thrift request/response")
	logrus.Warn("Before using the service don't forget to implement those.")
	logrus.Warn("---------------------------------------------------------------------------------------")
	return nil
}

func NewThriftInitGenerator() *ThriftInitGenerator {
	return &ThriftInitGenerator{}
}

type AddGRPCGenerator struct {
}

func (sg *AddGRPCGenerator) Generate(name string) error {
	g := NewServiceInitGenerator()
	te := template.NewEngine()
	defaultFs := fs.Get()
	path, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	sfile := path + defaultFs.FilePathSeparator() + fname
	b, err := defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	iname, err := te.ExecuteString(viper.GetString("service.interface_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Service %s was not found", name))
	}
	p := parser.NewFileParser()
	s, err := defaultFs.ReadFile(sfile)
	if err != nil {
		return err
	}
	f, err := p.Parse([]byte(s))
	if err != nil {
		return err
	}
	var iface *parser.Interface
	for _, v := range f.Interfaces {
		if v.Name == iname {
			iface = &v
		}
	}
	if iface == nil {
		return errors.New(fmt.Sprintf("Could not find the service interface in `%s`", sfile))
	}
	toKeep := []parser.Method{}
	for _, v := range iface.Methods {
		isOk := false
		for _, p := range v.Parameters {
			if p.Type == "context.Context" {
				isOk = true
				break
			}
		}
		if string(v.Name[0]) == strings.ToLower(string(v.Name[0])) {
			logrus.Warnf("The method '%s' is private and will be ignored", v.Name)
			continue
		}
		if len(v.Results) == 0 {
			logrus.Warnf("The method '%s' does not have any return value and will be ignored", v.Name)
			continue
		}
		if !isOk {
			logrus.Warnf("The method '%s' does not have a context and will be ignored", v.Name)
		}
		if isOk {
			toKeep = append(toKeep, v)
		}

	}
	iface.Methods = toKeep
	if len(iface.Methods) == 0 {
		return errors.New("The service has no method please implement the interface methods")
	}
	return g.generateGRPCTransport(name, iface)
}

func NewAddGRPCGenerator() *AddGRPCGenerator {
	return &AddGRPCGenerator{}
}

type AddHttpGenerator struct {
}

func (sg *AddHttpGenerator) Generate(name string) error {
	g := NewServiceInitGenerator()
	te := template.NewEngine()
	defaultFs := fs.Get()
	path, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	sfile := path + defaultFs.FilePathSeparator() + fname
	b, err := defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	iname, err := te.ExecuteString(viper.GetString("service.interface_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Service %s was not found", name))
	}
	p := parser.NewFileParser()
	s, err := defaultFs.ReadFile(sfile)
	if err != nil {
		return err
	}
	f, err := p.Parse([]byte(s))
	if err != nil {
		return err
	}
	var iface *parser.Interface
	for _, v := range f.Interfaces {
		if v.Name == iname {
			iface = &v
		}
	}
	if iface == nil {
		return errors.New(fmt.Sprintf("Could not find the service interface in `%s`", sfile))
	}
	toKeep := []parser.Method{}
	for _, v := range iface.Methods {
		isOk := false
		for _, p := range v.Parameters {
			if p.Type == "context.Context" {
				isOk = true
				break
			}
		}
		if string(v.Name[0]) == strings.ToLower(string(v.Name[0])) {
			logrus.Warnf("The method '%s' is private and will be ignored", v.Name)
			continue
		}
		if len(v.Results) == 0 {
			logrus.Warnf("The method '%s' does not have any return value and will be ignored", v.Name)
			continue
		}
		if !isOk {
			logrus.Warnf("The method '%s' does not have a context and will be ignored", v.Name)
		}
		if isOk {
			toKeep = append(toKeep, v)
		}

	}
	iface.Methods = toKeep
	if len(iface.Methods) == 0 {
		return errors.New("The service has no method please implement the interface methods")
	}
	return g.generateHttpTransport(name, iface)
}
func NewAddHttpGenerator() *AddHttpGenerator {
	return &AddHttpGenerator{}
}

type AddThriftGenerator struct {
}

func (sg *AddThriftGenerator) Generate(name string) error {
	g := NewServiceInitGenerator()
	te := template.NewEngine()
	defaultFs := fs.Get()
	path, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	fname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	sfile := path + defaultFs.FilePathSeparator() + fname
	b, err := defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	iname, err := te.ExecuteString(viper.GetString("service.interface_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Service %s was not found", name))
	}
	p := parser.NewFileParser()
	s, err := defaultFs.ReadFile(sfile)
	if err != nil {
		return err
	}
	f, err := p.Parse([]byte(s))
	if err != nil {
		return err
	}
	var iface *parser.Interface
	for _, v := range f.Interfaces {
		if v.Name == iname {
			iface = &v
		}
	}
	if iface == nil {
		return errors.New(fmt.Sprintf("Could not find the service interface in `%s`", sfile))
	}
	toKeep := []parser.Method{}
	for _, v := range iface.Methods {
		isOk := false
		for _, p := range v.Parameters {
			if p.Type == "context.Context" {
				isOk = true
				break
			}
		}
		if string(v.Name[0]) == strings.ToLower(string(v.Name[0])) {
			logrus.Warnf("The method '%s' is private and will be ignored", v.Name)
			continue
		}
		if len(v.Results) == 0 {
			logrus.Warnf("The method '%s' does not have any return value and will be ignored", v.Name)
			continue
		}
		if !isOk {
			logrus.Warnf("The method '%s' does not have a context and will be ignored", v.Name)
		}
		if isOk {
			toKeep = append(toKeep, v)
		}

	}
	iface.Methods = toKeep
	if len(iface.Methods) == 0 {
		return errors.New("The service has no method please implement the interface methods")
	}
	return g.generateThriftTransport(name, iface)
}
func NewAddThriftGenerator() *AddThriftGenerator {
	return &AddThriftGenerator{}
}
