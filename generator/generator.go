package generator

import (
	"fmt"
	"github.com/kujtimiihoxha/gk/fs"
	"github.com/kujtimiihoxha/gk/parser"
	"github.com/kujtimiihoxha/gk/utils"
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

	pp, err := utils.GetProjectPath()
	if err != nil {
		logrus.Debug("get project path fail, exit")
		return err
	}

	// new service
	{
		logrus.Info("Service Generating...")
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

		fname, err := te.ExecuteString(viper.GetString("service.file_name"), map[string]string{
			"ServiceName": name,
		})
		logrus.Debug(fmt.Sprintf("Service file name: %s", fname))
		if err != nil {
			return err
		}

		err = defaultFs.MkdirAll(path)
		logrus.Debug(fmt.Sprintf("Creating folder structure : %s", path))
		if err != nil {
			return err
		}

		fp := path + defaultFs.FilePathSeparator() + fname
		b, err := defaultFs.Exists(fp)
		if err != nil {
			return err
		}

		if b && !viper.GetBool("gk_force") {
			logrus.Info(fmt.Sprintf("Generating service: %s", name))
		} else {
			logrus.Info("Generating " + fp)
		}

		err = fs.NewDefaultFs(path).WriteFile(fname, f.String(), viper.GetBool("gk_force"))
		if err != nil {
			return err
		}
	}

	cepath, err := te.ExecuteString(viper.GetString("custom_errors.path"), map[string]string{"ServiceName": name})
	if err != nil {
		return err
	}

	// custom response
	{
		logrus.Info("Custom Responses Generating...")

		crpath, err := te.ExecuteString(viper.GetString("custom_responses.path"), map[string]string{"ServiceName": name})
		if err != nil {
			return err
		}
		err = defaultFs.MkdirAll(crpath)
		if err != nil {
			return err
		}

		// response/responses.go
		{
			crrname, err := te.ExecuteString(viper.GetString("custom_responses.responses_file_name"), map[string]string{"ServiceName": name})
			if err != nil {
				return err
			}

			logrus.Debug(fmt.Sprintf("Creating %s in %s", crrname, crpath))
			crrStr, err := te.Execute("custom_responses.go", nil)
			if err != nil {
				return err
			}

			crrfile := crpath + defaultFs.FilePathSeparator() + crrname
			b, err := defaultFs.Exists(crrfile)
			if err != nil {
				return err
			}
			if b && !viper.GetBool("gk_force") {
				logrus.Info("custom response/responses.go exists, skip re-generate")
			} else {
				logrus.Info("Generating " + crrfile)
			}

			err = fs.NewDefaultFs(crpath).WriteFile(crrname, crrStr, viper.GetBool("gk_force"))
			if err != nil {
				return err
			}

		}

		// response/errors.go
		{
			crename, err := te.ExecuteString(viper.GetString("custom_responses.errors_file_name"), map[string]string{"ServiceName": name})
			if err != nil {
				return err
			}

			logrus.Debug(fmt.Sprintf("Creating %s in %s", crename, crpath))
			creStr, err := te.Execute("custom_responses_error.go", map[string]string{"ErrorsPackage": pp + defaultFs.FilePathSeparator() + cepath})
			if err != nil {
				return err
			}

			crefile := crpath + defaultFs.FilePathSeparator() + crename
			b, err := defaultFs.Exists(crefile)
			if err != nil {
				return err
			}
			if b && !viper.GetBool("gk_force") {
				logrus.Info("custom response/errors.go exists, skip re-generate")
			} else {
				logrus.Info("Generating " + crefile)
			}

			err = defaultFs.WriteFile(crefile, creStr, viper.GetBool("gk_force"))
			if err != nil {
				return err
			}
		}

		// response/decode.go
		{
			crdname, err := te.ExecuteString(viper.GetString("custom_responses.decode_file_name"), nil)
			if err != nil {
				return err
			}

			logrus.Debug(fmt.Sprintf("Creating %s in %s", crdname, crpath))
			creStr, err := te.Execute("custom_responses_decode.go", map[string]string{"ErrorsPackage": pp + defaultFs.FilePathSeparator() + cepath})
			if err != nil {
				return err
			}

			crefile := crpath + defaultFs.FilePathSeparator() + crdname
			b, err := defaultFs.Exists(crefile)
			if err != nil {
				return err
			}
			if b && !viper.GetBool("gk_force") {
				logrus.Info("custom response/decode.go exists, skip re-generate")
			} else {
				logrus.Info("Generating " + crefile)
			}

			err = defaultFs.WriteFile(crefile, creStr, viper.GetBool("gk_force"))
			if err != nil {
				return err
			}
		}

		// response/httpstatus.go
		{
			crhname, err := te.ExecuteString(viper.GetString("custom_responses.httpstatus_file_name"), nil)
			if err != nil {
				return err
			}

			logrus.Debug(fmt.Sprintf("Creating %s in %s", crhname, crpath))
			creStr, err := te.Execute("custom_responses_httpstatus.go", map[string]string{"ErrorsPackage": pp + defaultFs.FilePathSeparator() + cepath})
			if err != nil {
				return err
			}

			crefile := crpath + defaultFs.FilePathSeparator() + crhname
			b, err := defaultFs.Exists(crefile)
			if err != nil {
				return err
			}
			if b && !viper.GetBool("gk_force") {
				logrus.Info("custom response/httpstatus.go exists, skip re-generate")
			} else {
				logrus.Info("Generating " + crefile)
			}

			err = defaultFs.WriteFile(crefile, creStr, viper.GetBool("gk_force"))
			if err != nil {
				return err
			}
		}
	}

	// custom error
	// errors/errors.go
	{
		logrus.Info("Custom Errors Generating...")

		cepath, err := te.ExecuteString(viper.GetString("custom_errors.path"), map[string]string{"ServiceName": name})
		if err != nil {
			return err
		}

		err = defaultFs.MkdirAll(cepath)
		if err != nil {
			return err
		}

		cename, err := te.ExecuteString(viper.GetString("custom_errors.file_name"), map[string]string{"ServiceName": name})
		if err != nil {
			return err
		}

		logrus.Debug(fmt.Sprintf("Creating %s in %s", cename, cepath))
		ceStr, err := te.Execute("custom_errors.go", nil)
		if err != nil {
			return err
		}

		cefile := cepath + defaultFs.FilePathSeparator() + cename
		b, err := defaultFs.Exists(cefile)
		if err != nil {
			return err
		}
		if b && !viper.GetBool("gk_force") {
			logrus.Info("custom errors/errors.go exists, skip re-generate")
		} else {
			logrus.Info("Generating " + cefile)
		}

		err = defaultFs.WriteFile(cefile, ceStr, viper.GetBool("gk_force"))
		if err != nil {
			return err
		}
	}
	return nil
}

func NewServiceGenerator() *ServiceGenerator {
	return &ServiceGenerator{}
}
