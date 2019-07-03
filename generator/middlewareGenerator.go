package generator

import (
	"errors"
	"fmt"
	"strings"

	"github.com/kujtimiihoxha/gk/fs"
	"github.com/kujtimiihoxha/gk/parser"
	"github.com/kujtimiihoxha/gk/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/tools/imports"

	template "github.com/kujtimiihoxha/gk/templates"
)

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
		y = append(y, parser.NewNameType(strings.ToLower(v.Name), "metrics.Counter"))
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
		Vars:    append(y, parser.NewNameType("next", fmt.Sprintf("%sService", utils.ToUpperFirstCamelCase(name)))),
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
