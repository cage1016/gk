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
		parser.NewNameType("", "\"github.com/kelseyhightower/envconfig\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/metrics\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/metrics/prometheus\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/sd\""),
		parser.NewNameType("stdopentracing", "\"github.com/opentracing/opentracing-go\""),
		parser.NewNameType("zipkinot", "\"github.com/openzipkin-contrib/zipkin-go-opentracing\""),
		parser.NewNameType("", "\"github.com/openzipkin/zipkin-go\""),
		parser.NewNameType("zipkinhttp", "\"github.com/openzipkin/zipkin-go/reporter/http\""),
		parser.NewNameType("", "\"github.com/uber/jaeger-client-go\""),
		parser.NewNameType("jconfig", "\"github.com/uber/jaeger-client-go/config\""),
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
		parser.NewNameType("transportsgrpc", "\""+transportsImport+"/grpc\""),
		parser.NewNameType("transportshttp", "\""+transportsImport+"/http\""),
	}

	// config struct
	configStrct := parser.NewStruct("Config", []parser.NamedTypeValue{})
	configStrct.Name = "Config"
	vars := []parser.NamedTypeValue{
		parser.NewNameTypeValueWithTags("ServiceName", "string", "", fmt.Sprintf(`envconfig:"QS_SERVICE_NAME" default:"%s"`, name)),
		parser.NewNameTypeValueWithTags("ServiceHost", "string", "", `envconfig:"QS_SERVICE_HOST" default:"localhost"`),
		parser.NewNameTypeValueWithTags("LogLevel", "string", "", `envconfig:"QS_LOG_LEVEL" default:"error"`),
		parser.NewNameTypeValueWithTags("HttpPort", "string", "", `envconfig:"QS_HTTP_PORT" default:"8180"`),
		parser.NewNameTypeValueWithTags("GrpcPort", "string", "", `envconfig:"QS_GRPC_PORT" default:"8181"`),
		parser.NewNameTypeValueWithTags("ZipkinV2URL", "string", "", `envconfig:"QS_ZIPKIN_V2_URL"`),
		parser.NewNameTypeValueWithTags("JaegerURL", "string", "", `envconfig:"QS_JAEGER_URL"`),
	}
	configStrct.Vars = append(configStrct.Vars, vars...)
	f.Structs = append(f.Structs, configStrct)

	// main function
	mainFunc := parser.NewMethod(
		"main",
		parser.NamedTypeValue{},
		`var logger log.Logger
		{
			logger = log.NewLogfmtLogger(os.Stderr)
			logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		}
		
		var cfg Config
		err := envconfig.Process("qs", &cfg)
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}

		logger = level.NewFilter(logger, level.AllowInfo())
		logger = log.With(logger, "service", cfg.ServiceName)
		logger = log.With(logger, "caller", log.DefaultCaller)
		level.Info(logger).Log("version", service.Version, "commitHash", service.CommitHash, "buildTimeStamp", service.BuildTimeStamp)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		tracer, closer := initJaeger(cfg.ServiceName, cfg.JaegerURL, logger)
		defer closer.Close()

		zipkinTracer := initZipkin(cfg.ServiceName, cfg.HttpPort, cfg.ZipkinV2URL, logger)
		service := NewServer(logger)
		endpoints := endpoints.New(service, logger, tracer, zipkinTracer)

		hs := health.NewServer()
		hs.SetServingStatus(cfg.ServiceName, healthgrpc.HealthCheckResponse_SERVING)

		wg := &sync.WaitGroup{}

		go startHTTPServer(ctx, wg, endpoints, tracer, zipkinTracer, cfg.HttpPort, logger)
		go startGRPCServer(ctx, wg, endpoints, tracer, zipkinTracer, cfg.GrpcPort, hs, logger)
	
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
	
		cancel()
		wg.Wait()
	
		fmt.Println("main: all goroutines have told us they've finished")`,
		[]parser.NamedTypeValue{},
		[]parser.NamedTypeValue{},
	)
	f.Methods = append(f.Methods, mainFunc)

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
		"initJaeger",
		parser.NamedTypeValue{},
		`if url == "" {
			return opentracing.NoopTracer{}, ioutil.NopCloser(nil)
		}
	
		tracer, closer, err := jconfig.Configuration{
			ServiceName: svcName,
			Sampler: &jconfig.SamplerConfig{
				Type:  jaeger.SamplerTypeConst,
				Param: 1,
			},
			Reporter: &jconfig.ReporterConfig{
				LocalAgentHostPort: url,
				LogSpans:           true,
			},
		}.NewTracer()
		if err != nil {
			level.Error(logger).Log("msg", fmt.Sprintf("Failed to init Jaeger: %s", err))
			os.Exit(1)
		}
	
		opentracing.SetGlobalTracer(tracer)
		return tracer, closer`,
		[]parser.NamedTypeValue{
			parser.NewNameType("svcName", "string"),
			parser.NewNameType("url", "string"),
			parser.NewNameType("logger", "log.Logger"),
		},
		[]parser.NamedTypeValue{
			parser.NewNameType("", "opentracing.Tracer"),
			parser.NewNameType("", "io.Closer"),
		},
	)
	f.Methods = append(f.Methods, initOpentracingFunc)

	// initZipkin
	body = `if zipkinV2URL != "" {
				var (
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
		`wg.Add(1)
				defer wg.Done()
			
				if port == "" {
					level.Error(logger).Log("protocol", "HTTP", "exposed", port, "err", "port is not assigned exist")
					return
				}
			
				p := fmt.Sprintf(":%s", port)
				// create a server
				srv := &http.Server{Addr: p, Handler: transportshttp.NewHTTPHandler(endpoints, tracer, zipkinTracer, logger)}
				level.Info(logger).Log("protocol", "HTTP", "exposed", port)
				go func() {
					// service connections
					if err := srv.ListenAndServe(); err != nil {
						level.Info(logger).Log("Listen", err)
					}
				}()
			
				<-ctx.Done()
			
				// shut down gracefully, but wait no longer than 5 seconds before halting
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
			
				// ignore error since it will be "Err shutting down server : context canceled"
				srv.Shutdown(shutdownCtx)
			
				level.Info(logger).Log("protocol", "HTTP", "Shutdown", "http server gracefully stopped")`,
		[]parser.NamedTypeValue{
			parser.NewNameType("ctx", "context.Context"),
			parser.NewNameType("wg", "*sync.WaitGroup"),
			parser.NewNameType("endpoints", "endpoints.Endpoints"),
			parser.NewNameType("tracer", "stdopentracing.Tracer"),
			parser.NewNameType("zipkinTracer", "*zipkin.Tracer"),
			parser.NewNameType("port", "string"),
			parser.NewNameType("logger", "log.Logger"),
		},
		[]parser.NamedTypeValue{},
	)
	f.Methods = append(f.Methods, startHTTPServerFunc)

	// startGRPCServer
	body = fmt.Sprintf(`wg.Add(1)
								defer wg.Done()
							
								p := fmt.Sprintf(":%%s", port)
								listener, err := net.Listen("tcp", p)
								if err != nil {
									level.Error(logger).Log("protocol", "GRPC", "listen", port, "err", err)
									os.Exit(1)
								}
							
								var server *grpc.Server
								level.Info(logger).Log("protocol", "GRPC", "exposed", port)
								server = grpc.NewServer(grpc.UnaryInterceptor(kitgrpc.Interceptor))
								pb.Register%sServer(server, transportsgrpc.MakeGRPCServer(endpoints, tracer, zipkinTracer, logger))
								healthgrpc.RegisterHealthServer(server, hs)
								reflection.Register(server)
							
								go func() {
									// service connections
									err = server.Serve(listener)
									if err != nil {
										fmt.Printf("grpc serve : %%s\n", err)
									}
								}()
							
								<-ctx.Done()
							
								// ignore error since it will be "Err shutting down server : context canceled"
								server.GracefulStop()
							
								fmt.Println("grpc server gracefully stopped")`, utils.ToUpperFirstCamelCase(name))

	startGRPCServerFunc := parser.NewMethod(
		"startGRPCServer",
		parser.NamedTypeValue{},
		body,
		[]parser.NamedTypeValue{
			parser.NewNameType("ctx", "context.Context"),
			parser.NewNameType("wg", "*sync.WaitGroup"),
			parser.NewNameType("endpoints", "endpoints.Endpoints"),
			parser.NewNameType("tracer", "stdopentracing.Tracer"),
			parser.NewNameType("zipkinTracer", "*zipkin.Tracer"),
			parser.NewNameType("port", "string"),
			parser.NewNameType("hs", "*health.Server"),
			parser.NewNameType("logger", "log.Logger"),
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
