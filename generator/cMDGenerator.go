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
		parser.NewNameType("", "\"google.golang.org/grpc/credentials\""),
		parser.NewNameType("", "\"sourcegraph.com/sourcegraph/appdash\""),
		parser.NewNameType("appdashot", "\"sourcegraph.com/sourcegraph/appdash/opentracing\""),
		parser.NewNameType("kitgrpc", "\"github.com/go-kit/kit/transport/grpc\""),
		parser.NewNameType("", ""),
		parser.NewNameType("pb", fmt.Sprintf(`"%s/pb/%s"`, projectPath, strings.ToLower(name))),
		parser.NewNameType("", "\""+endpointsImport+"\""),
		parser.NewNameType("", "\""+serviceImport+"\""),
		parser.NewNameType("", "\""+transportsImport+"\""),
	}

	// constants
	{
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defConsulHost", "string", `"localhost"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defConsulPort", "string", `"8500"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defZipkinV1URL", "string", `""`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defZipkinV2URL", "string", `""`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defLightstepToken", "string", `""`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defAppdashAddr", "string", `""`))

		f.Constants = append(f.Constants, parser.NewNameTypeValue("defNameSpace", "string", "\"gokitconsul\""))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defServiceName", "string", fmt.Sprintf(`"%s"`, name)))

		f.Constants = append(f.Constants, parser.NewNameTypeValue("defLogLevel", "string", `"error"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defServiceHost", "string", `"localhost"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defHTTPPort", "string", `"8180"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defGRPCPort", "string", `"8181"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defServerCert", "string", `""`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defServerKey", "string", `""`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defClientTLS", "string", `"false"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("defCACerts", "string", `""`))

		f.Constants = append(f.Constants, parser.NewNameTypeValue("envConsulHost", "string", `"QS_CONSULT_HOST"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envConsultPort", "string", `"QS_CONSULT_PORT"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envZipkinV1URL", "string", `"QS_ZIPKIN_V1_URL"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envZipkinV2URL", "string", `"QS_ZIPKIN_V2_URL"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envLightstepToken", "string", `"QS_LIGHT_STEP_TOKEN"`))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envAppdashAddr", "string", `"QS_APPDASH_ADDR"`))

		f.Constants = append(f.Constants, parser.NewNameTypeValue("envNameSpace", "string", fmt.Sprintf(`"QS_%s_NAMESPACE"`, name)))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envServiceName", "string", fmt.Sprintf(`"QS_%s_SERVICE_NAME"`, name)))

		f.Constants = append(f.Constants, parser.NewNameTypeValue("envLogLevel", "string", fmt.Sprintf(`"QS_%s_LOG_LEVEL"`, strings.ToUpper(name))))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envServiceHost", "string", fmt.Sprintf(`"QS_%s_SERVICE_HOST"`, strings.ToUpper(name))))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envHTTPPort", "string", fmt.Sprintf(`"QS_%s_HTTP_PORT"`, strings.ToUpper(name))))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envGRPCPort", "string", fmt.Sprintf(`"QS_%s_GRPC_PORT"`, strings.ToUpper(name))))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envServerCert", "string", fmt.Sprintf(`"QS_%s_SERVER_CERT"`, strings.ToUpper(name))))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envServerKey", "string", fmt.Sprintf(`"QS_%s_SERVER_KEY"`, strings.ToUpper(name))))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envClientTLS", "string", fmt.Sprintf(`"QS_%s_CLIENT_TLS"`, strings.ToUpper(name))))
		f.Constants = append(f.Constants, parser.NewNameTypeValue("envCACerts", "string", fmt.Sprintf(`"QS_%s_CA_CERTS"`, strings.ToUpper(name))))
	}

	// config struct
	configStrct := parser.NewStruct("config", []parser.NamedTypeValue{})
	configStrct.Name = "config"
	vars := []parser.NamedTypeValue{
		parser.NewNameType("nameSpace", "string"),
		parser.NewNameType("serviceName", "string"),
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
	
		errs := make(chan error, 2)
		grpcServer, httpHandler := NewServer(cfg, logger)
		go startHTTPServer(cfg, httpHandler, logger, errs)
		go startGRPCServer(cfg, grpcServer, logger, errs)
	
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
		`tls, err := strconv.ParseBool(env(envClientTLS, defClientTLS))
				if err != nil {
					level.Error(logger).Log("envClientTLS", envClientTLS, "error", err)
				}

				cfg.nameSpace = env(envNameSpace, defNameSpace)
				cfg.serviceName = env(envServiceName, defServiceName)
				cfg.logLevel = env(envLogLevel, defLogLevel)
				cfg.clientTLS = tls
				cfg.caCerts = env(envCACerts, defCACerts)
				cfg.serviceHost = env(envServiceHost, defServiceHost)
				cfg.httpPort = env(envHTTPPort, defHTTPPort)
				cfg.grpcPort = env(envGRPCPort, defGRPCPort)
				cfg.serverCert = env(envServerCert, defServerCert)
				cfg.serverKey = env(envServerKey, defServerKey)
				cfg.consulHost = env(envConsulHost, defConsulHost)
				cfg.consultPort = env(envConsultPort, defConsulPort)
				cfg.zipkinV1URL = env(envZipkinV1URL, defZipkinV1URL)
				cfg.zipkinV2URL = env(envZipkinV2URL, defZipkinV2URL)
				cfg.lightstepToken = env(envLightstepToken, defLightstepToken)
				cfg.appdashAddr = env(envAppdashAddr, defAppdashAddr)
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
	body := `var tracer stdopentracing.Tracer
			{
				if cfg.zipkinV1URL != "" && cfg.zipkinV2URL == "" {
					logger.Log("tracer", "Zipkin", "type", "OpenTracing", "URL", cfg.zipkinV1URL)
					collector, err := zipkinot.NewHTTPCollector(cfg.zipkinV1URL)
					if err != nil {
						logger.Log("err", err)
						os.Exit(1)
					}
					defer collector.Close()
					var (
						debug       = false
						hostPort    = fmt.Sprintf("localhost:%s", cfg.httpPort)
						serviceName = cfg.serviceName
					)
					recorder := zipkinot.NewRecorder(collector, debug, hostPort, serviceName)
					tracer, err = zipkinot.NewTracer(recorder)
					if err != nil {
						logger.Log("err", err)
						os.Exit(1)
					}
				} else if cfg.lightstepToken != "" {
					logger.Log("tracer", "LightStep")
					tracer = lightstep.NewTracer(lightstep.Options{AccessToken: cfg.lightstepToken})
					defer lightstep.FlushLightStepTracer(tracer)
				} else if cfg.appdashAddr != "" {
					logger.Log("tracer", "Appdash", "addr", cfg.appdashAddr)
					tracer = appdashot.NewTracer(appdash.NewRemoteCollector(cfg.appdashAddr))
				} else {
					tracer = stdopentracing.GlobalTracer()
				}
			}
		
			var zipkinTracer *zipkin.Tracer
			{
				var (
					err           error
					hostPort      = fmt.Sprintf("localhost:%s", cfg.httpPort)
					serviceName   = cfg.serviceName
					useNoopTracer = (cfg.zipkinV2URL == "")
					reporter      = zipkinhttp.NewReporter(cfg.zipkinV2URL)
				)
				//defer reporter.Close()
				zEP, _ := zipkin.NewEndpoint(serviceName, hostPort)
				zipkinTracer, err = zipkin.NewTracer(reporter, zipkin.WithLocalEndpoint(zEP), zipkin.WithNoopTracer(useNoopTracer))
				if err != nil {
					logger.Log("err", err)
					os.Exit(1)
				}
				if !useNoopTracer {
					logger.Log("tracer", "Zipkin", "type", "Native", "URL", cfg.zipkinV2URL)
				}
			}
		
			var (
				requestCount   metrics.Counter
				requestLatency metrics.Histogram
				fieldKeys      []string
			)
			{
				fieldKeys = []string{"method", "error"}
				requestCount = prometheus.NewCounterFrom(stdprometheus.CounterOpts{Namespace: cfg.nameSpace, Subsystem: cfg.serviceName, Name: "request_count", Help: "Number of requests received."}, fieldKeys)
				requestLatency = prometheus.NewSummaryFrom(stdprometheus.SummaryOpts{Namespace: cfg.nameSpace, Subsystem: cfg.serviceName, Name: "request_latency_microseconds", Help: "Total duration of requests in microseconds."}, fieldKeys)
			}
		
			var duration metrics.Histogram
			{
				duration = prometheus.NewSummaryFrom(stdprometheus.SummaryOpts{Namespace: cfg.nameSpace, Subsystem: cfg.serviceName, Name: "request_duration_ns", Help: "Request duration in nanoseconds."}, []string{"method", "success"})
			}
		
			service := service.New(logger, requestCount, requestLatency)
			endpoints := endpoints.New(service, logger, duration, tracer, zipkinTracer)
			httpHandler := transports.NewHTTPHandler(endpoints, tracer, zipkinTracer, logger)
			grpcServer := transports.MakeGRPCServer(endpoints, tracer, zipkinTracer, logger)
		
			return grpcServer, httpHandler`
	newServiceFunc := parser.NewMethod(
		"NewServer",
		parser.NamedTypeValue{},
		body,
		[]parser.NamedTypeValue{
			parser.NewNameType("cfg", "config"),
			parser.NewNameType("logger", "log.Logger"),
		},
		[]parser.NamedTypeValue{
			parser.NewNameType("", fmt.Sprintf("pb.%sServer", utils.ToUpperFirstCamelCase(name))),
			parser.NewNameType("", "http.Handler"),
		},
	)
	f.Methods = append(f.Methods, newServiceFunc)

	// startHTTPServer
	startHTTPServerFunc := parser.NewMethod(
		"startHTTPServer",
		parser.NamedTypeValue{},
		`p := fmt.Sprintf(":%s", cfg.httpPort)
				if cfg.serverCert != "" || cfg.serverKey != "" {
					level.Info(logger).Log("serviceName", cfg.serviceName, "protocol", "HTTP", "exposed", cfg.httpPort, "certFile", cfg.serverCert, "keyFile", cfg.serverKey)
					errs <- http.ListenAndServeTLS(p, cfg.serverCert, cfg.serverKey, httpHandler)
				} else {
					level.Info(logger).Log("serviceName", cfg.serviceName, "protocol", "HTTP", "exposed", cfg.httpPort)
					errs <- http.ListenAndServe(p, httpHandler)
				}`,
		[]parser.NamedTypeValue{
			parser.NewNameType("cfg", "config"),
			parser.NewNameType("httpHandler", "http.Handler"),
			parser.NewNameType("logger", "log.Logger"),
			parser.NewNameType("errs", "chan error"),
		},
		[]parser.NamedTypeValue{},
	)
	f.Methods = append(f.Methods, startHTTPServerFunc)

	// startGRPCServer
	body = fmt.Sprintf(`p := fmt.Sprintf(":%%s", cfg.grpcPort)
			listener, err := net.Listen("tcp", p)
			if err != nil {
				level.Error(logger).Log("serviceName", cfg.serviceName, "protocol", "GRPC", "listen", cfg.grpcPort, "err", err)
				os.Exit(1)
			}

			var server *grpc.Server
			if cfg.serverCert != "" || cfg.serverKey != "" {
				creds, err := credentials.NewServerTLSFromFile(cfg.serverCert, cfg.serverKey)
				if err != nil {
					level.Error(logger).Log("serviceName", cfg.serviceName, "certificates", creds, "err", err)
					os.Exit(1)
				}
				level.Info(logger).Log("serviceName", cfg.serviceName, "protocol", "GRPC", "exposed", cfg.grpcPort, "certFile", cfg.serverCert, "keyFile", cfg.serverKey)
				server = grpc.NewServer(grpc.UnaryInterceptor(kitgrpc.Interceptor), grpc.Creds(creds))
			} else {
				level.Info(logger).Log("serviceName", cfg.serviceName, "protocol", "GRPC", "exposed", cfg.grpcPort)
				server = grpc.NewServer(grpc.UnaryInterceptor(kitgrpc.Interceptor))
			}	
			pb.Register%sServer(server, grpcServer)
			errs <- server.Serve(listener)`, utils.ToUpperFirstCamelCase(name))

	startGRPCServerFunc := parser.NewMethod(
		"startGRPCServer",
		parser.NamedTypeValue{},
		body,
		[]parser.NamedTypeValue{
			parser.NewNameType("cfg", "config"),
			parser.NewNameType("grpcServer", fmt.Sprintf("pb.%sServer", utils.ToUpperFirstCamelCase(name))),
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
