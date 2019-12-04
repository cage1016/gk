package generator

import (
	"fmt"

	"github.com/kujtimiihoxha/gk/fs"
	"github.com/kujtimiihoxha/gk/parser"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	template "github.com/kujtimiihoxha/gk/templates"
)

var SUPPORTED_TRANSPORTS = []string{"http", "grpc", "thrift"}

type ServiceGenerator struct {
}

func (sg *ServiceGenerator) Generate(name string) error {
	f := parser.NewFile()
	f.Package = "service"
	te := template.NewEngine()
	defaultFs := fs.Get()

	// new service
	{
		logrus.Info(fmt.Sprintf("Generating service: %s", name))
		iname, err := te.ExecuteString(viper.GetString("service.interface_name"), map[string]string{
			"ServiceName": name,
		})
		logrus.Debug(fmt.Sprintf("Service interface name : %s", iname))
		if err != nil {
			return err
		}

		//f.Interfaces = []parser.Interface{
		//	parser.NewInterfaceWithComment(iname, fmt.Sprintf(`%s implements yor service methods.
		//	e.x: Foo(ctx context.Context,s string)(rs string, err error)`, iname), []parser.Method{}),
		//}
		svcInterface := []parser.Interface{
			parser.NewInterfaceWithComment(iname, `Service describes a service that adds things together
		Implement yor service methods methods.
		e.x: Foo(ctx context.Context, s string)(rs string, err error)`, []parser.Method{
				parser.NewMethodWithComment("Foo", "[method=post,expose=true]", parser.NamedTypeValue{}, "", []parser.NamedTypeValue{
					parser.NewNameType("ctx", "context.Context"),
					parser.NewNameType("s", "string"),
				}, []parser.NamedTypeValue{
					parser.NewNameType("res", "string"),
					parser.NewNameType("err", "error"),
				}),
			}),
		}
		f.Interfaces = svcInterface

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
		err = fs.NewDefaultFs(path).WriteFile(fname, f.String(), false)
		if err != nil {
			return err
		}
	}

	// custom response
	{
		logrus.Info("Custom Responses Generating...")

		crpath, err := te.ExecuteString(viper.GetString("custom_responses.path"), map[string]string{"ServiceName": name})
		if err != nil {
			return err
		}
		crname, err := te.ExecuteString(viper.GetString("custom_responses.file_name"), map[string]string{"ServiceName": name})
		if err != nil {
			return err
		}

		err = defaultFs.MkdirAll(crpath)
		logrus.Debug(fmt.Sprintf("Creating %s in %s", crname, crpath))
		if err != nil {
			return err
		}

		crStr, err := te.Execute("custom_responses.go", nil)
		if err != nil {
			return err
		}

		crfile := crpath + defaultFs.FilePathSeparator() + crname
		b, err := defaultFs.Exists(crfile)
		if err != nil {
			return err
		}
		if b {
			logrus.Info("custom response exists, skip re-generate")
		}

		err = defaultFs.WriteFile(crfile, crStr, true)
		if err != nil {
			return err
		}
	}

	// custom error
	{
		logrus.Info("Custom Errors Generating...")

		cepath, err := te.ExecuteString(viper.GetString("custom_errors.path"), map[string]string{"ServiceName": name})
		if err != nil {
			return err
		}
		cename, err := te.ExecuteString(viper.GetString("custom_errors.file_name"), map[string]string{"ServiceName": name})
		if err != nil {
			return err
		}

		err = defaultFs.MkdirAll(cepath)
		logrus.Debug(fmt.Sprintf("Creating %s in %s", cename, cepath))
		if err != nil {
			return err
		}

		ceStr, err := te.Execute("custom_errors.go", nil)
		if err != nil {
			return err
		}

		cefile := cepath + defaultFs.FilePathSeparator() + cename
		b, err := defaultFs.Exists(cefile)
		if err != nil {
			return err
		}
		if b {
			logrus.Info("custom errors exists, skip re-generate")
		}

		err = defaultFs.WriteFile(cefile, ceStr, true)
		if err != nil {
			return err
		}
	}
	return nil
}

func NewServiceGenerator() *ServiceGenerator {
	return &ServiceGenerator{}
}
