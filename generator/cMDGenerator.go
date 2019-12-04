package generator

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/kujtimiihoxha/gk/fs"
	"github.com/kujtimiihoxha/gk/parser"
	"github.com/kujtimiihoxha/gk/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	template "github.com/kujtimiihoxha/gk/templates"
)

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
	f := parser.NewFile()
	f.Package = "main"

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

	f.Imports = []parser.NamedTypeValue{
		parser.NewNameType("", "\"fmt\""),
		parser.NewNameType("", "\"net\""),
		parser.NewNameType("", "\"net/http\""),
		parser.NewNameType("", "\"os\""),
		parser.NewNameType("", "\"os/signal\""),
		parser.NewNameType("", "\"strconv\""),
		parser.NewNameType("", "\"syscall\""),
		parser.NewNameType("", ""),
		parser.NewNameType("", "\"github.com/go-kit/kit/log\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/log/level\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/metrics\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/metrics/prometheus\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/sd\""),
		parser.NewNameType("stdopentracing", "\"github.com/opentracing/opentracing-go\""),
		parser.NewNameType("zipkinot", "\"github.com/openzipkin-contrib/zipkin-go-opentracing\""),
		parser.NewNameType("", "\"github.com/openzipkin/zipkin-go\""),
		parser.NewNameType("zipkinhttp", "\"github.com/openzipkin/zipkin-go/reporter/http\""),
		parser.NewNameType("stdprometheus", "\"github.com/prometheus/client_golang/prometheus\""),
		parser.NewNameType("", "\"google.golang.org/grpc\""),
		parser.NewNameType("", "\"google.golang.org/grpc/health\""),
		parser.NewNameType("", "\"google.golang.org/grpc/credentials\""),
		parser.NewNameType("healthgrpc", "\"google.golang.org/grpc/health/grpc_health_v1\""),
		parser.NewNameType("", "\"google.golang.org/grpc/reflection\""),
		parser.NewNameType("kitgrpc", "\"github.com/go-kit/kit/transport/grpc\""),
		parser.NewNameType("", ""),
		parser.NewNameType("pb", fmt.Sprintf(`"%s/pb/%s"`, projectPath, strings.ToLower(name))),
		parser.NewNameType("", "\""+endpointsImport+"\""),
		parser.NewNameType("", "\""+serviceImport+"\""),
		parser.NewNameType("", "\""+transportsImport+"\""),
	}

	// constants
	{
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defZipkinV2URL", "string", `""`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defServiceName", "string", fmt.Sprintf(`"%s"`, name)))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defLogLevel", "string", `"error"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defServiceHost", "string", `"localhost"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defHTTPPort", "string", `"8180"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defGRPCPort", "string", `"8181"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envZipkinV2URL", "string", `"QS_ZIPKIN_V2_URL"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envServiceName", "string", fmt.Sprintf(`"QS_%s_SERVICE_NAME"`, strings.ToUpper(name))))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envLogLevel", "string", fmt.Sprintf(`"QS_%s_LOG_LEVEL"`, strings.ToUpper(name))))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envServiceHost", "string", fmt.Sprintf(`"QS_%s_SERVICE_HOST"`, strings.ToUpper(name))))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envHTTPPort", "string", fmt.Sprintf(`"QS_%s_HTTP_PORT"`, strings.ToUpper(name))))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envGRPCPort", "string", fmt.Sprintf(`"QS_%s_GRPC_PORT"`, strings.ToUpper(name))))
	}

	// config struct
	configStrct := parser.NewStruct("config", []parser.NamedTypeValue{})
	configStrct.Name = "config"
	vars := []parser.NamedTypeValue{
		parser.NewNameType("serviceName", "string"),
		parser.NewNameType("logLevel", "string"),
		parser.NewNameType("serviceHost", "string"),
		parser.NewNameType("httpPort", "string"),
		parser.NewNameType("grpcPort", "string"),
		parser.NewNameType("zipkinV2URL", "string"),
	}
	configStrct.Vars = append(configStrct.Vars, vars...)
	f.Structs = append(f.Structs, configStrct)

	// env function
	envFunc := parser.NewMethodWithComment(
		"env",
		`Env reads specified environment variable. If no value has been found,
		fallback is returned.`,
		parser.NamedTypeValue{},
		`if v := os.Getenv(key); v != "" {
					return v
				}
				return fallback`,
		[]parser.NamedTypeValue{
			parser.NewNameType("key", "string"),
			parser.NewNameType("fallback", "string"),
		},
		[]parser.NamedTypeValue{
			parser.NewNameType("", "string"),
		},
	)
	f.Methods = append(f.Methods, envFunc)

	// main function
	mainFunc := parser.NewMethod(
		"main",
		parser.NamedTypeValue{},
		`var logger log.Logger
		{
			logger = log.NewLogfmtLogger(os.Stderr)
			logger = level.NewFilter(logger, level.AllowInfo())
			logger = log.With(logger, "ts", log.DefaultTimestampUTC)
			logger = log.With(logger, "caller", log.DefaultCaller)
		}
		cfg := loadConfig(logger)
		logger = log.With(logger, "service", cfg.serviceName)

		tracer := initOpentracing()
		zipkinTracer := initZipkin(cfg.serviceName, cfg.httpPort, cfg.zipkinV2URL, logger)
		service := NewServer(logger)
		endpoints := endpoints.New(service, logger, tracer, zipkinTracer)
		
		errs := make(chan error, 2)
		hs := health.NewServer()
		hs.SetServingStatus(cfg.serviceName, healthgrpc.HealthCheckResponse_SERVING)
		go startHTTPServer(endpoints, tracer, zipkinTracer, cfg.httpPort, logger, errs)
		go startGRPCServer(endpoints, tracer, zipkinTracer, cfg.grpcPort, hs, logger, errs)
	
		go func() {
			c := make(chan os.Signal)
			signal.Notify(c, syscall.SIGINT)
			errs <- fmt.Errorf("%s", <-c)
		}()
	
		err := <-errs	
		level.Info(logger).Log("serviceName", cfg.serviceName, "terminated", err)`,
		[]parser.NamedTypeValue{},
		[]parser.NamedTypeValue{},
	)
	f.Methods = append(f.Methods, mainFunc)

	// loadConfig function
	loadConfigFunc := parser.NewMethod(
		"loadConfig",
		parser.NamedTypeValue{},
		`cfg.serviceName = env(envServiceName, defServiceName)
				cfg.logLevel = env(envLogLevel, defLogLevel)
				cfg.serviceHost = env(envServiceHost, defServiceHost)
				cfg.httpPort = env(envHTTPPort, defHTTPPort)
				cfg.grpcPort = env(envGRPCPort, defGRPCPort)
				cfg.zipkinV2URL = env(envZipkinV2URL, defZipkinV2URL)
				return cfg`,
		[]parser.NamedTypeValue{
			parser.NewNameType("logger", "log.Logger"),
		},
		[]parser.NamedTypeValue{
			parser.NewNameType("cfg", "config"),
		},
	)
	f.Methods = append(f.Methods, loadConfigFunc)

	// newService
	body := `service := service.New(logger)
			return service`
	newServiceFunc := parser.NewMethod(
		"NewServer",
		parser.NamedTypeValue{},
		body,
		[]parser.NamedTypeValue{
			parser.NewNameType("logger", "log.Logger"),
		},
		[]parser.NamedTypeValue{
			parser.NewNameType("", fmt.Sprintf("service.%sService", utils.ToUpperFirstCamelCase(name))),
		},
	)
	f.Methods = append(f.Methods, newServiceFunc)

	// initOpentracing
	initOpentracingFunc := parser.NewMethod(
		"initOpentracing",
		parser.NamedTypeValue{},
		`return stdopentracing.GlobalTracer()`,
		[]parser.NamedTypeValue{},
		[]parser.NamedTypeValue{
			parser.NewNameType("", "stdopentracing.Tracer"),
		},
	)
	f.Methods = append(f.Methods, initOpentracingFunc)

	// initZipkin
	body = `var (
				err           error
				hostPort      = fmt.Sprintf("localhost:%s", httpPort)
				useNoopTracer = (zipkinV2URL == "")
				reporter      = zipkinhttp.NewReporter(zipkinV2URL)
			)
			zEP, _ := zipkin.NewEndpoint(serviceName, hostPort)
			zipkinTracer, err = zipkin.NewTracer(reporter, zipkin.WithLocalEndpoint(zEP), zipkin.WithNoopTracer(useNoopTracer))
			if err != nil {
				logger.Log("err", err)
				os.Exit(1)
			}
			if !useNoopTracer {
				logger.Log("tracer", "Zipkin", "type", "Native", "URL", zipkinV2URL)
			}
		
			return`
	initZipkinFunc := parser.NewMethod(
		"initZipkin",
		parser.NamedTypeValue{},
		body,
		[]parser.NamedTypeValue{
			parser.NewNameType("serviceName", ""),
			parser.NewNameType("httpPort", ""),
			parser.NewNameType("zipkinV2URL", "string"),
			parser.NewNameType("logger", "log.Logger"),
		},
		[]parser.NamedTypeValue{
			parser.NewNameType("zipkinTracer", "*zipkin.Tracer"),
		},
	)
	f.Methods = append(f.Methods, initZipkinFunc)

	// startHTTPServer
	startHTTPServerFunc := parser.NewMethod(
		"startHTTPServer",
		parser.NamedTypeValue{},
		`p := fmt.Sprintf(":%s", port)
				level.Info(logger).Log("protocol", "HTTP", "exposed", port)
				errs <- http.ListenAndServe(p, transports.NewHTTPHandler(endpoints, tracer, zipkinTracer, logger))`,
		[]parser.NamedTypeValue{
			parser.NewNameType("endpoints", "endpoints.Endpoints"),
			parser.NewNameType("tracer", "stdopentracing.Tracer"),
			parser.NewNameType("zipkinTracer", "*zipkin.Tracer"),
			parser.NewNameType("port", "string"),
			parser.NewNameType("logger", "log.Logger"),
			parser.NewNameType("errs", "chan error"),
		},
		[]parser.NamedTypeValue{},
	)
	f.Methods = append(f.Methods, startHTTPServerFunc)

	// startGRPCServer
	body = fmt.Sprintf(`p := fmt.Sprintf(":%%s", port)
			listener, err := net.Listen("tcp", p)
			if err != nil {
				level.Error(logger).Log("protocol", "GRPC", "listen", port, "err", err)
				os.Exit(1)
			}

			var server *grpc.Server
			level.Info(logger).Log("protocol", "GRPC", "exposed", port)
			server = grpc.NewServer(grpc.UnaryInterceptor(kitgrpc.Interceptor))	
			pb.Register%sServer(server, transports.MakeGRPCServer(endpoints, tracer, zipkinTracer, logger))
			healthgrpc.RegisterHealthServer(server, hs)
			reflection.Register(server)
			errs <- server.Serve(listener)`, utils.ToUpperFirstCamelCase(name))

	startGRPCServerFunc := parser.NewMethod(
		"startGRPCServer",
		parser.NamedTypeValue{},
		body,
		[]parser.NamedTypeValue{
			parser.NewNameType("endpoints", "endpoints.Endpoints"),
			parser.NewNameType("tracer", "stdopentracing.Tracer"),
			parser.NewNameType("zipkinTracer", "*zipkin.Tracer"),
			parser.NewNameType("port", "string"),
			parser.NewNameType("hs", "*health.Server"),
			parser.NewNameType("logger", "log.Logger"),
			parser.NewNameType("errs", "chan error"),
		},
		[]parser.NamedTypeValue{},
	)
	f.Methods = append(f.Methods, startGRPCServerFunc)

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

	return defaultFs.WriteFile(tfile, f.String(), false)
}

func NewCMDGenerator() *CMDGenerator {
	return &CMDGenerator{}
}
