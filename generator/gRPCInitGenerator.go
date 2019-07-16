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

	pbpath, err := te.ExecuteString(viper.GetString("pb.path"), map[string]string{
		"ServiceName": name,
		//"TransportType": "grpc",
	})
	b, err = defaultFs.Exists(path)
	if err != nil {
		return err
	}

	pbgofile := pbpath + defaultFs.FilePathSeparator() + utils.ToLowerSnakeCase(name) + ".pb.go"
	b, err = defaultFs.Exists(pbgofile)
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
		parser.NewNameType("", "\"context\""),
		parser.NewNameType("", "\"errors\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/circuitbreaker\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/endpoint\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/log\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/ratelimit\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/tracing/opentracing\""),
		parser.NewNameType("", "\"github.com/go-kit/kit/tracing/zipkin\""),
		parser.NewNameType("grpctransport", "\"github.com/go-kit/kit/transport/grpc\""),
		parser.NewNameType("stdopentracing", "\"github.com/opentracing/opentracing-go\""),
		parser.NewNameType("stdzipkin", "\"github.com/openzipkin/zipkin-go\""),
		parser.NewNameType("", "\"github.com/sony/gobreaker\""),
		parser.NewNameType("", "\"golang.org/x/time/rate\""),
		parser.NewNameType("", fmt.Sprintf("\"%s\"", pbImport)),
		parser.NewNameType("", fmt.Sprintf("\"%s\"", endpointsImport)),
		parser.NewNameType("", fmt.Sprintf("\"%s\"", serviceImport)),
	}

	grpcStruct := parser.NewStruct("grpcServer", []parser.NamedTypeValue{})

	for _, v := range iface.Methods {
		grpcStruct.Vars = append(grpcStruct.Vars, parser.NewNameType(
			utils.ToLowerFirstCamelCase(v.Name),
			"grpctransport.Handler",
		))

		handler.Methods = append(handler.Methods, parser.NewMethod(
			v.Name,
			parser.NewNameType("s", "*grpcServer"),
			fmt.Sprintf(
				`_, rp, err := s.%s.ServeGRPC(ctx, req)
					if err != nil {
						return nil, grpcEncodeError(err)
					}
					rep = rp.(*pb.%sReply)
					return rep, nil`,
				utils.ToLowerFirstCamelCase(v.Name),
				v.Name,
			),
			[]parser.NamedTypeValue{
				parser.NewNameType("ctx", "context.Context"),
				parser.NewNameType("req", fmt.Sprintf("*pb.%sRequest", v.Name)),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("rep", fmt.Sprintf("*pb.%sReply", v.Name)),
				parser.NewNameType("err", "error"),
			},
		))
	}

	// NewGRPCServer
	{
		m := parser.NewMethodWithComment(
			"MakeGRPCServer",
			`MakeGRPCServer makes a set of endpoints available as a gRPC server.`,
			parser.NamedTypeValue{},
			`	// Zipkin GRPC Server Trace can either be instantiated per gRPC method with a
					// provided operation name or a global tracing service can be instantiated
					// without an operation name and fed to each Go kit gRPC server as a
					// ServerOption.
					// In the latter case, the operation name will be the endpoint's grpc method
					// path if used in combination with the Go kit gRPC Interceptor.
					//
					// In this example, we demonstrate a global Zipkin tracing service with
					// Go kit gRPC Interceptor.
					zipkinServer := zipkin.GRPCServerTrace(zipkinTracer)
				
					options := []grpctransport.ServerOption{
						grpctransport.ServerErrorLogger(logger),
						zipkinServer,
					}
				
					return &grpcServer{`,
			[]parser.NamedTypeValue{
				parser.NewNameType("endpoints", "endpoints.Endpoints"),
				parser.NewNameType("otTracer", "stdopentracing.Tracer"),
				parser.NewNameType("zipkinTracer", "*stdzipkin.Tracer"),
				parser.NewNameType("logger", "log.Logger"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("req", fmt.Sprintf("pb.%sServer", utils.ToUpperFirstCamelCase(name))),
			},
		)
		handler.Methods = append(handler.Methods, m)

		//fmt.Println(handler.String())

		for _, v := range iface.Methods {
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
					"decodeGRPC"+v.Name+"Request",
					fmt.Sprintf(
						`decodeGRPC%sRequest is a transport/grpc.DecodeRequestFunc that converts a
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
					"encodeGRPC"+v.Name+"Response",
					fmt.Sprintf(
						`encodeGRPC%sResponse is a transport/grpc.EncodeResponseFunc that converts a
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

			body := fmt.Sprintf(
				`%s : grpctransport.NewServer(
							endpoints.%sEndpoint,
							decodeGRPC%sRequest,
							encodeGRPC%sResponse,
							append(options, grpctransport.ServerBefore(opentracing.GRPCToContext(otTracer, "%s", logger)))...,
						),
						`, utils.ToLowerFirstCamelCase(v.Name), v.Name, v.Name, v.Name, v.Name)

			handler.Methods[len(iface.Methods)].Body += "\n" + body
		}
		handler.Methods[len(iface.Methods)].Body += `}`
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
			`// We construct a single ratelimiter middleware, to limit the total outgoing
					// QPS from this client to all methods on the remote instance. We also
					// construct per-endpoint circuitbreaker middlewares to demonstrate how
					// that's done, although they could easily be combined into a single breaker
					// for the entire remote instance, too.
					limiter := ratelimit.NewErroringLimiter(rate.NewLimiter(rate.Every(time.Second), 100))
				
					// Zipkin GRPC Client Trace can either be instantiated per gRPC method with a
					// provided operation name or a global tracing client can be instantiated
					// without an operation name and fed to each Go kit client as ClientOption.
					// In the latter case, the operation name will be the endpoint's grpc method
					// path.
					//
					// In this example, we demonstrace a global tracing client.
					zipkinClient := zipkin.GRPCClientTrace(zipkinTracer)
				
					// global client middlewares
					options := []grpctransport.ClientOption{
						zipkinClient,
					}`,
			[]parser.NamedTypeValue{
				parser.NewNameType("conn", "*grpc.ClientConn"),
				parser.NewNameType("otTracer", "stdopentracing.Tracer"),
				parser.NewNameType("zipkinTracer", "*stdzipkin.Tracer"),
				parser.NewNameType("logger", "log.Logger"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("", fmt.Sprintf("service.%sService", utils.ToUpperFirstCamelCase(name))),
			},
		))

		for _, v := range iface.Methods {
			// encodeGRPC Request
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
					"encodeGRPC"+v.Name+"Request",
					fmt.Sprintf(
						`encodeGRPC%sRequest is a transport/grpc.EncodeRequestFunc that converts a
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

			// decodeGRPC Response
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
					"decodeGRPC"+v.Name+"Response",
					fmt.Sprintf(
						`decodeGRPC%sResponse is a transport/grpc.DecodeResponseFunc that converts a
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

			fcname := utils.ToLowerFirstCamelCase(v.Name)
			body := fmt.Sprintf(`// The %s endpoint is the same thing, with slightly different
				// middlewares to demonstrate how to specialize per-endpoint.
				var %sEndpoint endpoint.Endpoint
				{
					%sEndpoint = grpctransport.NewClient(
						conn,
						"pb.%s",
						"%s",
						encodeGRPC%sRequest,
						decodeGRPC%sResponse,
						pb.%sReply{},
						append(options, grpctransport.ClientBefore(opentracing.ContextToGRPC(otTracer, logger)))...,
					).Endpoint()
					%sEndpoint = opentracing.TraceClient(otTracer, "%s")(%sEndpoint)
					%sEndpoint = limiter(%sEndpoint)
					%sEndpoint = circuitbreaker.Gobreaker(gobreaker.NewCircuitBreaker(gobreaker.Settings{
						Name:    "%s",
						Timeout: 30 * time.Second,
					}))(%sEndpoint)
				}`,
				v.Name,
				fcname,
				fcname,
				utils.ToUpperFirstCamelCase(name),
				v.Name,
				v.Name,
				v.Name,
				v.Name,
				fcname, v.Name, fcname,
				fcname, fcname,
				fcname,
				v.Name,
				fcname,
			)

			handler.Methods[len(iface.Methods)*3+1].Body += "\n\n" + body
		}

		l := len(iface.Methods) + 2
		body := make([]string, l)
		body[0] = "return endpoints.Endpoints{"
		for i, v := range iface.Methods {
			body[i+1] = fmt.Sprintf(`%sEndpoint: %sEndpoint,`, v.Name, utils.ToLowerFirstCamelCase(v.Name))
		}
		body[l-1] = "}"
		handler.Methods[len(iface.Methods)*3+1].Body += "\n\n" + strings.Join(body, "\n")
	}

	// annoying helper functions
	{
		handler.Methods = append(handler.Methods, parser.NewMethod(
			"grpcEncodeError",
			parser.NamedTypeValue{},
			`if err == nil {
						return nil
					}
				
					st, ok := status.FromError(err)
					if ok {
						return status.Error(st.Code(), st.Message())
					}
					switch err {
					default:
						return status.Error(codes.Internal, "internal server error")
					}`,
			[]parser.NamedTypeValue{
				parser.NewNameType("err", "error"),
			},
			[]parser.NamedTypeValue{
				parser.NewNameType("", "error"),
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
