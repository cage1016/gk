package generator

import (
	"errors"
	"fmt"
	"go/format"
	"os"
	"runtime"
	"strings"

	"github.com/kujtimiihoxha/gk/fs"
	"github.com/kujtimiihoxha/gk/parser"
	template "github.com/kujtimiihoxha/gk/templates"
	"github.com/kujtimiihoxha/gk/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type ServiceInitGenerator struct {
}

func (sg *ServiceInitGenerator) Generate(name string) error {
	te := template.NewEngine()
	defaultFs := fs.Get()

	path, err := te.ExecuteString(viper.GetString("service.path"), map[string]string{
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

	// imports
	f.Imports = append(f.Imports, []parser.NamedTypeValue{
		parser.NewNameType("", "\"github.com/go-kit/kit/log\""),
	}...)

	// alias type
	f.AliasType = []parser.NamedTypeValue{{
		Name:     "Middleware",
		Type:     fmt.Sprintf("func(%sService) %sService", utils.ToUpperFirstCamelCase(name), utils.ToUpperFirstCamelCase(name)),
		HasValue: false,
		Comment:  "// Middleware describes a service (as opposed to endpoint) middleware.",
	}}

	stubName, err := te.ExecuteString(viper.GetString("service.struct_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	stub := parser.NewStructWithComment(
		stubName,
		"the concrete implementation of service interface",
		[]parser.NamedTypeValue{parser.NewNameType("logger", "log.Logger")},
	)
	exists := false
	for _, v := range f.Structs {
		if v.Name == stub.Name {
			logrus.Infof("Service `%s` structure already exists so it will not be recreated.", stub.Name)
			exists = true
		}
	}
	if !exists {
		f.Structs = append(f.Structs, parser.NewStructWithComment(
			stubName,
			"the concrete implementation of service interface",
			[]parser.NamedTypeValue{parser.NewNameType("logger", "log.Logger")},
		))
	}
	exists = false
	for _, v := range f.Methods {
		if v.Name == "New" {
			logrus.Infof("Service `%s` New function already exists so it will not be recreated", stub.Name)
			exists = true
		}
	}

	if !exists {
		body := []string{
			fmt.Sprintf("var svc %s", iname),
			"{",
			fmt.Sprintf("svc = &%s{logger: logger}", stub.Name),
			"svc = LoggingMiddleware(logger)(svc)",
			"}",
			"return svc",
		}
		f.Methods = append(f.Methods, parser.NewMethodWithComment(
			"New",
			`New return a new instance of the service.
			If you want to add service middleware this is the place to put them.`,
			parser.NamedTypeValue{},
			strings.Join(body, "\n"),
			[]parser.NamedTypeValue{
				parser.NewNameType("logger", "log.Logger"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("s", iname),
			},
		))
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
			f.Methods = append(f.Methods, parser.NewMethodWithComment(
				m.Name,
				fmt.Sprintf(`Implement the business logic of %s`, m.Name),
				parser.NewNameType(strings.ToLower(iface.Name[:2]), "*"+stub.Name),
				"",
				m.Parameters,
				m.Results,
			))
		}
	}

	err = defaultFs.WriteFile(sfile, f.String(), true)
	if err != nil {
		return err
	}
	err = sg.generateEndpoints(name, iface)
	if err != nil {
		return err
	}
	err = sg.generateEndpointsRequests(name, iface)
	if err != nil {
		return err
	}
	err = sg.generateEndpointsResponse(name, iface)
	if err != nil {
		return err
	}
	err = sg.generateTransport(name, iface, transport)
	if err != nil {
		return err
	}
	err = sg.generateServiceLoggingMiddleware(name, path, iface)
	if err != nil {
		return err
	}
	err = sg.generateEndpointMiddleware(name, epath, iface)
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
		parser.NewNameType("", "\"bytes\""),
		parser.NewNameType("", "\"context\""),
		parser.NewNameType("", "\"encoding/json\""),
		parser.NewNameType("", "\"errors\""),
		parser.NewNameType("", "\"io/ioutil\""),
		parser.NewNameType("", "\"net/http\""),
		parser.NewNameType("", "\"net/url\""),
		parser.NewNameType("", "\"strings\""),
		parser.NewNameType("", "\"time\""),
		parser.NewNameType("", ""),
		parser.NewNameType("", "\"github.com/go-zoo/bone\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/circuitbreaker\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/endpoint\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/log\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/ratelimit\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/tracing/opentracing\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/tracing/zipkin\""),
		parser.NewNameType("httptransport", "\"github.com/go-kit/kit/transport/http\""),
		parser.NewNameType("stdopentracing", "\"github.com/opentracing/opentracing-go\""),
		parser.NewNameType("stdzipkin", "\"github.com/openzipkin/zipkin-go\""),
		parser.NewNameType("", "\"github.com/prometheus/client_golang/prometheus/promhttp\""),
		parser.NewNameType("", "\"github.com/sony/gobreaker\""),
		parser.NewNameType("", "\"golang.org/x/time/rate\""),
		parser.NewNameType("", ""),
		parser.NewNameType("", "\""+endpointsImport+"\""),
		parser.NewNameType("", "\""+serviceImport+"\""),
	}

	// JSONErrorDecoder
	handlerFile.Methods = append(handlerFile.Methods, parser.NewMethod(
		"JSONErrorDecoder",
		parser.NamedTypeValue{},
		`contentType := r.Header.Get("Content-Type")
				if !strings.Contains(contentType, "application/json") {
					return fmt.Errorf("expected JSON formatted error, got Content-Type %s", contentType)
				}
				var w errorWrapper
				if err := json.NewDecoder(r.Body).Decode(&w); err != nil {
					return err
				}
				return errors.New(w.Error)`,
		[]parser.NamedTypeValue{
			parser.NewNameType("r", "*http.Response"),
		},
		[]parser.NamedTypeValue{
			parser.NewNameType("", "error"),
		},
	))

	// NewHTTPHandler
	{
		handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
			"NewHTTPHandler",
			`NewHTTPHandler returns a handler that makes a set of endpoints available on
			 predefined paths.`,
			parser.NamedTypeValue{},
			`	// Zipkin HTTP Server Trace can either be instantiated per endpoint with a
					// provided operation name or a global tracing service can be instantiated
					// without an operation name and fed to each Go kit endpoint as ServerOption.
					// In the latter case, the operation name will be the endpoint's http method.
					// We demonstrate a global tracing service here.
					zipkinServer := zipkin.HTTPServerTrace(zipkinTracer)
				
					options := []httptransport.ServerOption{
						httptransport.ServerErrorEncoder(httpEncodeError),
						httptransport.ServerErrorLogger(logger),
						zipkinServer,
					}

					m := bone.New()`,
			[]parser.NamedTypeValue{
				parser.NewNameType("endpoints", "endpoints.Endpoints"),
				parser.NewNameType("otTracer", "stdopentracing.Tracer"),
				parser.NewNameType("zipkinTracer", "*stdzipkin.Tracer"),
				parser.NewNameType("logger", "log.Logger"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("", "http.Handler"),
			},
		))
		for _, m := range iface.Methods {
			cc := m.GetCustomField()
			if cc.Expose == false{
				continue
			}

			var mi string
			if strings.ToUpper(cc.Method) == "POST" {
				mi = fmt.Sprintf(`var req endpoints.%sRequest
											err := json.NewDecoder(r.Body).Decode(&req)
											return req,err`, m.Name)
			}else{
				mi = fmt.Sprintf(`var req endpoints.%sRequest
											return req, nil`, m.Name)
			}

			handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
				fmt.Sprintf("decodeHTTP%sRequest", m.Name),
				fmt.Sprintf(`decodeHTTP%sRequest is a transport/http.DecodeRequestFunc that decodes a
					 JSON-encoded request from the HTTP request body. Primarily useful in a server.`,
					m.Name),
				parser.NamedTypeValue{},
				mi,
				[]parser.NamedTypeValue{
					parser.NewNameType("_", "context.Context"),
					parser.NewNameType("r", "*http.Request"),
				},
				[]parser.NamedTypeValue{
					parser.NewNameType("", "interface{}"),
					parser.NewNameType("", "error"),
				},
			))
			handlerFile.Methods[1].Body += "\n" + fmt.Sprintf(`m.%s("/%s", httptransport.NewServer(
        endpoints.%sEndpoint,
        decodeHTTP%sRequest,
        httptransport.EncodeJSONResponse,
		append(options, httptransport.ServerBefore(opentracing.HTTPToContext(otTracer, "%s", logger)))...,
    ))`, utils.ToUpperFirstCamelCase(cc.Method), utils.ToLowerSnakeCase(m.Name), m.Name, m.Name, m.Name)
		}

		handlerFile.Methods[1].Body += "\n" + `m.Get("/metrics", promhttp.Handler())
												return m`
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
					
						// We construct a single ratelimiter middleware, to limit the total outgoing
						// QPS from this client to all methods on the remote instance. We also
						// construct per-endpoint circuitbreaker middlewares to demonstrate how
						// that's done, although they could easily be combined into a single breaker
						// for the entire remote instance, too.
						limiter := ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), 100))
					
						// Zipkin HTTP Client Trace can either be instantiated per endpoint with a
						// provided operation name or a global tracing client can be instantiated
						// without an operation name and fed to each Go kit endpoint as ClientOption.
						// In the latter case, the operation name will be the endpoint's http method.
						zipkinClient := zipkin.HTTPClientTrace(zipkinTracer)
					
						// global client middlewares
						options := []httptransport.ClientOption{
							zipkinClient,
						}

						e := endpoints.Endpoints{}
					
						// Each individual endpoint is an http/transport.Client (which implements
						// endpoint.Endpoint) that gets wrapped with various middlewares. If you
						// made your own client library, you'd do this work there, so your server
						// could rely on a consistent set of client behavior.`,
			[]parser.NamedTypeValue{
				parser.NewNameType("instance", "string"),
				parser.NewNameType("otTracer", "stdopentracing.Tracer"),
				parser.NewNameType("zipkinTracer", "*stdzipkin.Tracer"),
				parser.NewNameType("logger", "log.Logger"),
			},
			[]parser.NamedTypeValue{
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
			cc := m.GetCustomField()
			if cc.Expose == false{
				continue
			}

			handlerFile.Methods = append(handlerFile.Methods, parser.NewMethodWithComment(
				fmt.Sprintf("encodeHTTP%sRequest", m.Name),
				fmt.Sprintf(`encodeHTTP%sRequest is a transport/http.EncodeRequestFunc that
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
				fmt.Sprintf("decodeHTTP%sResponse", m.Name),
				fmt.Sprintf(`decodeHTTP%sResponse is a transport/http.DecodeResponseFunc that decodes a
				JSON-encoded sum response from the HTTP response body. If the response has a
			    non-200 status code, we will interpret that as an error and attempt to decode
			    the specific error message from the response body. Primarily useful in a client.`, m.Name),
				parser.NamedTypeValue{},
				fmt.Sprintf(`if r.StatusCode != http.StatusOK {
										return nil, JSONErrorDecoder(r)
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

			fcname := utils.ToLowerFirstCamelCase(m.Name)
			handlerFile.Methods[iface.ExposeMethodLength()*1+2].Body += "\n" + fmt.Sprintf(
				`// The %s endpoint is the same thing, with slightly different
						// middlewares to demonstrate how to specialize per-endpoint.
						var %sEndpoint endpoint.Endpoint
						{
							%sEndpoint = httptransport.NewClient(
								"%s",
								copyURL(u, "/%s"),
								encodeHTTP%sRequest,
								decodeHTTP%sResponse,
								append(options, httptransport.ClientBefore(opentracing.ContextToHTTP(otTracer, logger)))...,
							).Endpoint()
							%sEndpoint = opentracing.TraceClient(otTracer, "%s")(%sEndpoint)
							%sEndpoint = zipkin.TraceEndpoint(zipkinTracer, "%s")(%sEndpoint)
							%sEndpoint = limiter(%sEndpoint)
							%sEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{
								Name:    "%s",
								Timeout: 30 * time.Second,
							}))(%sEndpoint)
							e.%sEndpoint = %sEndpoint
						}`,
				m.Name,
				fcname,
				fcname,
				strings.ToUpper(cc.Method),
				strings.ToLower(m.Name),
				m.Name,
				m.Name,
				fcname, m.Name, fcname,
				fcname, m.Name, fcname,
				fcname, fcname,
				fcname,
				m.Name,
				fcname,
				m.Name, utils.ToLowerFirstCamelCase(m.Name))

			handlerFile.Methods[iface.ExposeMethodLength()*1+2].Body += "\n"
		}
		handlerFile.Methods[iface.ExposeMethodLength()*1+2].Body += "\n" + `// Returning the endpoint.Set as a service.Service relies on the
	// endpoint.Set implementing the Service methods. That's just a simple bit
	// of glue code.
	return e, nil`
	}

	// httpEncodeError
	handlerFile.Methods = append(handlerFile.Methods, parser.NewMethod(
		"httpEncodeError",
		parser.NamedTypeValue{},
		`w.Header().Set("Content-Type", "application/json")
			
				if lberr, ok := err.(lb.RetryError); ok {
					st, _ := status.FromError(lberr.Final)
					w.WriteHeader(HTTPStatusFromCode(st.Code()))
					json.NewEncoder(w).Encode(errorWrapper{Error: st.Message()})
				} else {
					st, ok := status.FromError(err)
					if ok {
						w.WriteHeader(HTTPStatusFromCode(st.Code()))
						json.NewEncoder(w).Encode(errorWrapper{Error: st.Message()})
					} else {
						switch err {
						case io.ErrUnexpectedEOF:
							w.WriteHeader(http.StatusBadRequest)
						case io.EOF:
							w.WriteHeader(http.StatusBadRequest)
						default:
							switch err.(type) {
							case *json.SyntaxError:
								w.WriteHeader(http.StatusBadRequest)
							case *json.UnmarshalTypeError:
								w.WriteHeader(http.StatusBadRequest)
							default:
								w.WriteHeader(http.StatusInternalServerError)
							}
						}
						json.NewEncoder(w).Encode(errorWrapper{Error: err.Error()})
					}
				}`,
		[]parser.NamedTypeValue{
			parser.NewNameType("_", "context.Context"),
			parser.NewNameType("err", "error"),
			parser.NewNameType("w", "http.ResponseWriter"),
		},
		[]parser.NamedTypeValue{},
	))

	// errorWrapper
	handlerFile.Structs = append(handlerFile.Structs, parser.NewStruct(
		"errorWrapper",
		[]parser.NamedTypeValue{
			parser.NewNameType("Error", "string"),
		},
	))

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

	// errors
	errorsstr, err := te.Execute("errors.go", nil)
	if err != nil {
		return err
	}
	errorsfile := path + defaultFs.FilePathSeparator() + "errors.go"
	b, err = defaultFs.Exists(errorsfile)
	if err != nil {
		return err
	}
	if b {
		logrus.Info("errors.go already exists, skip re-generate")
	}
	err = defaultFs.WriteFile(errorsfile, errorsstr, true)
	if err != nil {
		return err
	}

	return defaultFs.WriteFile(tfile, handlerFile.String(), false)
}
func (sg *ServiceInitGenerator) generateGRPCTransport(name string, iface *parser.Interface) error {
	logrus.Info("Generating grpc transport...")
	te := template.NewEngine()
	defaultFs := fs.Get()

	path, err := te.ExecuteString(viper.GetString("pb.path"), map[string]string{
		"ServiceName": name,
		//"TransportType": "grpc",
	})
	b, err := defaultFs.Exists(path)
	if err != nil {
		return err
	}

	fname := utils.ToLowerSnakeCase(name)
	tfile := path + defaultFs.FilePathSeparator() + fname + ".proto"
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

	//
	type ProtobufModel struct {
		Name    string
		Methods []parser.Method
	}
	pbModel := ProtobufModel{Name: utils.ToUpperFirstCamelCase(name)}
	for _, v := range iface.Methods {
		cc := v.GetCustomField()
		if cc.Expose == false {
			continue
		}

		m := parser.Method{Name: v.Name}
		for k, kv := range v.Parameters {
			if kv.Type == "context.Context" {
				continue
			} else if kv.Type == "int" {
				kv.Type = "int32"
			}
			//利用 Method.Value 来传递 protobuf index，下标从 1 开始，由于 ctx 参数不用，则跨过 0 下标
			kv.Value = fmt.Sprintf("%v", k)
			kv.Name = utils.ToLowerFirstCamelCase(kv.Name)
			m.Parameters = append(m.Parameters, kv)
		}
		for k, kv := range v.Results {
			if kv.Type == "error" {
				kv.Type = "string"
			} else if kv.Type == "int" {
				kv.Type = "int32"
			}
			//利用 Method.Value 来传递 protobuf index，下标从 1 开始
			kv.Value = fmt.Sprintf("%v", k+1)
			kv.Name = utils.ToLowerFirstCamelCase(kv.Name)
			m.Results = append(m.Results, kv)
		}
		pbModel.Methods = append(pbModel.Methods, m)
	}

	protoTmpl, err := te.Execute("proto.pb", pbModel)
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

	endpointsPath, err := te.ExecuteString(viper.GetString("endpoints.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	b, err := defaultFs.Exists(endpointsPath)
	if err != nil {
		return err
	}

	endpointsFileName, err := te.ExecuteString(viper.GetString("endpoints.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	eFile := endpointsPath + defaultFs.FilePathSeparator() + endpointsFileName
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
		err = defaultFs.MkdirAll(endpointsPath)
		if err != nil {
			return err
		}
	}
	f := parser.NewFile()
	f.Package = "endpoints"

	f.Structs = []parser.Struct{
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
	f.Imports = []parser.NamedTypeValue{
		parser.NewNameType("", `"github.com/sony/gobreaker"`),
		parser.NewNameType("stdzipkin", `"github.com/openzipkin/zipkin-go"`),
		parser.NewNameType("stdopentracing", "\"github.com/opentracing/opentracing-go\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/endpoint\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/log\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/tracing/opentracing\""),
		parser.NewNameType("", "\""+serviceImport+"\""),
	}
	f.Methods = []parser.Method{
		parser.NewMethodWithComment(
			"New",
			"New return a new instance of the endpoint that wraps the provided service.",
			parser.NamedTypeValue{},
			"",
			[]parser.NamedTypeValue{
				parser.NewNameType("svc", "service."+iface.Name),
				parser.NewNameType("logger", "log.Logger"),
				parser.NewNameType("otTracer", "stdopentracing.Tracer"),
				parser.NewNameType("zipkinTracer", "*stdzipkin.Tracer"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("ep", "Endpoints"),
			},
		),
	}

	for _, v := range iface.Methods {
		cc := v.GetCustomField()

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

		tmplModel := map[string]interface{}{
			"Calling":  v,
			"Request":  req,
			"Response": res,
		}
		tRes, err := te.ExecuteString("{{template \"endpoint_func\" .}}", tmplModel)
		if err != nil {
			return err
		}

		if cc.Expose == false {
			f.Methods = append(f.Methods, parser.NewMethodWithComment(
				v.Name,
				fmt.Sprintf(`endpoint implement %s interface
							but do nothing with expose=false`, iface.Name),
				parser.NewNameType("e", "Endpoints"),
				`panic("implement me")`,
				v.Parameters,
				v.Results,
			))
			continue
		}
		f.Structs[0].Vars = append(f.Structs[0].Vars, parser.NewNameType(v.Name+"Endpoint", "endpoint.Endpoint"))

		f.Methods = append(f.Methods, parser.NewMethodWithComment(
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
		f.Methods = append(f.Methods, parser.NewMethodWithComment(
			v.Name,
			fmt.Sprintf(`%s implements the service interface, so Endpoints may be used as a service.
					  This is primarily useful in the context of a client library.`, v.Name),
			parser.NewNameType("e", "Endpoints"),
			tRes,
			v.Parameters,
			v.Results,
		))

		//
		lowerName := utils.ToLowerFirstCamelCase(v.Name)
		upperName := utils.ToUpperFirstCamelCase(v.Name)

		f.Methods[0].Body += fmt.Sprintf(`
		var %sEndpoint endpoint.Endpoint
		{
			method := "%s"
			%sEndpoint = Make%sEndpoint(svc)
            %sEndpoint = ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), 100))(%sEndpoint)
			%sEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{}))(%sEndpoint)
			%sEndpoint = opentracing.TraceServer(otTracer, method)(%sEndpoint)
			%sEndpoint = zipkin.TraceEndpoint(zipkinTracer,  method)(%sEndpoint)
			%sEndpoint = LoggingMiddleware(log.With(logger, "method", method))(%sEndpoint)
			ep.%sEndpoint = %sEndpoint
		}
		`, lowerName,
			lowerName,
			lowerName,
			upperName,
			lowerName,
			lowerName,
			lowerName,
			lowerName,
			lowerName,
			lowerName,
			lowerName,
			lowerName,
			lowerName,
			lowerName,
			upperName,
			lowerName)
	}
	f.Methods[0].Body += "\n\n return ep"
	return defaultFs.WriteFile(eFile, f.String(), false)
}
func (sg *ServiceInitGenerator) generateEndpointsRequests(name string, iface *parser.Interface) error {
	logrus.Info("Generating endpoints requests...")
	te := template.NewEngine()
	defaultFs := fs.Get()

	endpointsPath, err := te.ExecuteString(viper.GetString("endpoints.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	b, err := defaultFs.Exists(endpointsPath)
	if err != nil {
		return err
	}

	reqname, err := te.ExecuteString(viper.GetString("endpoints.requests_file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	eFile := endpointsPath + defaultFs.FilePathSeparator() + reqname
	if b {
		fex, err := defaultFs.Exists(eFile)
		if err != nil {
			return err
		}
		if fex {
			logrus.Errorf("Endpoints Requests for service `%s` exist", name)
			logrus.Info("If you are trying to add functions to a service use `gk update service [serviceName]`")
			return nil
		}
	} else {
		err = defaultFs.MkdirAll(endpointsPath)
		if err != nil {
			return err
		}
	}
	f := parser.NewFile()
	f.Package = "endpoints"

	f.Interfaces = append(f.Interfaces, parser.NewInterface(
		"Request",
		[]parser.Method{
			parser.NewMethod(
				"validate",
				parser.NamedTypeValue{},
				"",
				[]parser.NamedTypeValue{},
				[]parser.NamedTypeValue{
					parser.NewNameType("", "error"),
				},
			),
		},
	))

	for _, v := range iface.Methods {
		cc := v.GetCustomField()
		if cc.Expose == false {
			continue
		}

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
		f.Structs = append(f.Structs, req)

		//add Request interface method for response
		{
			f.Methods = append(f.Methods, parser.NewMethod(
				"validate",
				parser.NewNameType("r", v.Name+"Request"),
				fmt.Sprintf(`return nil// TBA`)+"\n",
				[]parser.NamedTypeValue{},
				[]parser.NamedTypeValue{
					parser.NewNameType("", "error"),
				},
			))
		}
	}

	nm := iface.ExposeMethodLength()
	var body = make([]string, nm*2+2)
	body[0] = "package endpoints"
	body[1] = f.Interfaces[0].String()

	for i := 0; i < nm; i++ {
		body[2*i+2] = f.Structs[i].String()
		body[2*i+3] = f.Methods[i].String()
	}
	return defaultFs.WriteFile(eFile, strings.Join(body, "\n\n"), false)
}

func (sg *ServiceInitGenerator) generateEndpointsResponse(name string, iface *parser.Interface) error {
	logrus.Info("Generating endpoints response...")
	te := template.NewEngine()
	defaultFs := fs.Get()

	endpointsPath, err := te.ExecuteString(viper.GetString("endpoints.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	b, err := defaultFs.Exists(endpointsPath)
	if err != nil {
		return err
	}

	resname, err := te.ExecuteString(viper.GetString("endpoints.responses_file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	eFile := endpointsPath + defaultFs.FilePathSeparator() + resname
	if b {
		fex, err := defaultFs.Exists(eFile)
		if err != nil {
			return err
		}
		if fex {
			logrus.Errorf("Endpoints Response for service `%s` exist", name)
			logrus.Info("If you are trying to add functions to a service use `gk update service [serviceName]`")
			return nil
		}
	} else {
		err = defaultFs.MkdirAll(endpointsPath)
		if err != nil {
			return err
		}
	}
	f := parser.NewFile()
	f.Package = "endpoints"

	for _, v := range iface.Methods {
		cc := v.GetCustomField()
		if cc.Expose == false {
			continue
		}

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
		res := parser.NewStructWithComment(
			v.Name+"Response",
			fmt.Sprintf(
				"%sResponse collects the response values for the %s method.",
				v.Name, v.Name,
			),
			resultPrams,
		)
		f.Structs = append(f.Structs, res)

		f.Vars = append(f.Vars, parser.NewNameTypeValue("_", "httptransport.Headerer", fmt.Sprintf(`(*%sResponse)(nil)`, v.Name)))
		f.Vars = append(f.Vars, parser.NewNameTypeValue("_", "httptransport.StatusCoder", fmt.Sprintf(`(*%sResponse)(nil)`, v.Name)))

		f.Methods = append(f.Methods, parser.NewMethod(
			"StatusCode",
			parser.NewNameType("r", v.Name+"Response"),
			fmt.Sprintf(`return http.StatusOK // TBA`)+"\n",
			[]parser.NamedTypeValue{},
			[]parser.NamedTypeValue{
				parser.NewNameType("", "int"),
			},
		))
		f.Methods = append(f.Methods, parser.NewMethod(
			"Headers",
			parser.NewNameType("r", v.Name+"Response"),
			fmt.Sprintf(`return http.Header{}`)+"\n",
			[]parser.NamedTypeValue{},
			[]parser.NamedTypeValue{
				parser.NewNameType("", "http.Header"),
			},
		))
	}

	nm := iface.ExposeMethodLength()
	var body = make([]string, 3+nm*3)
	tRes, err := te.ExecuteString("{{template \"vars\" .}}", f.Vars)
	if err != nil {
		return err
	}

	body[0] = "package endpoints" + "\n\n" + `import (
	"net/http"
	
	httptransport "github.com/go-kit/kit/transport/http"
)`
	a, _ := format.Source([]byte(strings.TrimSpace(tRes)))
	body[1] = string(a)
	for i := 0; i < nm; i++ {
		body[3*i+2] = f.Structs[i].String()
		body[3*i+3] = f.Methods[i*2+0].String()
		body[3*i+4] = f.Methods[i*2+1].String()
	}

	return defaultFs.WriteFile(eFile, strings.Join(body, "\n\n"), false)
}
func (mg *ServiceInitGenerator) generateEndpointMiddleware(name, path string, iface *parser.Interface) error {
	logrus.Info("Generating endpoints middleware...")
	te := template.NewEngine()
	defaultFs := fs.Get()
	f := parser.NewFile()
	f.Package = "endpoints"

	//
	mname, err := te.ExecuteString(viper.GetString("middleware.name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}

	// imports
	f.Imports = []parser.NamedTypeValue{
		parser.NewNameType("", "\"github.com/go-kit/kit/endpoint\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/log\""),
	}

	// LoggingMiddleware
	f.Methods = append(f.Methods, parser.NewMethodWithComment(
		"LoggingMiddleware",
		`LoggingMiddleware returns an endpoint middleware that logs the
					duration of each invocation, and the resulting error, if any.`,
		parser.NamedTypeValue{},
		`return func(next endpoint.Endpoint) endpoint.Endpoint {
					return func(ctx context.Context, request interface{}) (response interface{}, err error) {
						defer func(begin time.Time) {
							if err == nil {
								level.Info(logger).Log("transport_error", err, "took", time.Since(begin))
							} else {
								level.Error(logger).Log("transport_error", err, "took", time.Since(begin))
							}
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

	tfile := path + defaultFs.FilePathSeparator() + mname
	return defaultFs.WriteFile(tfile, f.String(), false)
}
func (mg *ServiceInitGenerator) generateServiceLoggingMiddleware(name, path string, iface *parser.Interface) error {
	logrus.Info("Generating service logging middleware...")
	te := template.NewEngine()
	defaultFs := fs.Get()
	f := parser.NewFile()
	f.Package = "service"

	f.Imports = append(f.Imports, []parser.NamedTypeValue{
		parser.NewNameType("", "\"github.com/go-kit/kit/log\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/metrics\""),
	}...)

	f.Methods = append(f.Methods, parser.NewMethodWithComment(
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
	))

	f.Structs = append(f.Structs, parser.Struct{
		Name:    "loggingMiddleware",
		Comment: "",
		Vars: []parser.NamedTypeValue{
			parser.NewNameType("logger", "log.Logger"),
			parser.NewNameType("next", fmt.Sprintf("%sService", utils.ToUpperFirstCamelCase(name))),
		},
	})

	for _, v := range iface.Methods {
		reqPrams := []parser.NamedTypeValue{}
		for _, p := range v.Parameters {
			if p.Type != "context.Context" {
				reqPrams = append(reqPrams, parser.NewNameType(p.Name, p.Type))
			}
		}
		resultPrams := []parser.NamedTypeValue{}
		for _, p := range v.Results {
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
		f.Methods = append(f.Methods, parser.NewMethod(
			v.Name,
			parser.NamedTypeValue{Name: "lm", Type: "loggingMiddleware"},
			tRes,
			v.Parameters,
			v.Results,
		))
	}

	lfile := path + defaultFs.FilePathSeparator() + "logging.go"
	err := defaultFs.WriteFile(lfile, f.String(), true)
	if err != nil {
		return err
	}
	return nil
}

func NewServiceInitGenerator() *ServiceInitGenerator {
	return &ServiceInitGenerator{}
}
