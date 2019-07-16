package generator

import (
	"errors"
	"fmt"
	"github.com/kujtimiihoxha/gk/fs"
	"github.com/kujtimiihoxha/gk/parser"
	template "github.com/kujtimiihoxha/gk/templates"
	"github.com/kujtimiihoxha/gk/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"strings"
)

type ConsulPatchGenerator struct {
}

func (cpg *ConsulPatchGenerator) Generate(name string) error {
	logrus.Info("Patching cmd consul...")
	te := template.NewEngine()
	defaultFs := fs.Get()

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

	cpath, err := te.ExecuteString(viper.GetString("cmd.path"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	cname, err := te.ExecuteString(viper.GetString("cmd.file_name"), map[string]string{
		"ServiceName": name,
	})
	if err != nil {
		return err
	}
	sfile := cpath + defaultFs.FilePathSeparator() + cname
	b, err := defaultFs.Exists(sfile)
	if err != nil {
		return err
	}
	if !b {
		return errors.New(fmt.Sprintf("Service %s cmd was not found", name))
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

	err = cpg.generateConsulRegister()
	if err != nil {
		return err
	}

	// patch main
	{
		// main function
		if !strings.Contains(f.Methods[1].Body, `consulAddres := fmt.Sprintf("%s:%s", cfg.consulHost, cfg.consultPort)`) {
			f.Methods[1].Body = strings.Replace(
				string(f.Methods[1].Body),
				"cfg := loadConfig(logger)",
				`cfg := loadConfig(logger)
	
				// consul
				{
					if cfg.consulHost != "" && cfg.consultPort != "" {
						consulAddres := fmt.Sprintf("%s:%s", cfg.consulHost, cfg.consultPort)
						servicePort, _ := strconv.Atoi(cfg.grpcPort)
						consulReg := grpcsr.NewConsulRegister(consulAddres, cfg.serviceName, servicePort, []string{cfg.nameSpace, cfg.serviceName}, logger)
						svcRegistar, err := consulReg.NewConsulGRPCRegister()
						defer svcRegistar.Deregister()
						if err != nil {
							level.Error(logger).Log(
								"consulAddres", consulAddres,
								"serviceName", cfg.serviceName,
								"servicePort", servicePort,
								"tags", []string{cfg.nameSpace, cfg.serviceName},
								"err", err,
							)
						}
						svcRegistar.Register()
					}
				}`,
				-1,
			)
		} else {
			logrus.Info("cmd has been patched. skip action")
			return nil
		}
	}

	// New Server
	{
		for _, v := range []int{0, 3} {
			for i, _ := range f.Methods[v].Results {
				f.Methods[v].Results[i].Name = ""
			}
		}
	}

	// startGRPCServer parameters
	{
		f.Methods[5].Body = strings.Replace(f.Methods[5].Body, "errs <- server.Serve(listener)",
			`grpc_health_v1.RegisterHealthServer(server, &service.HealthImpl{})
					errs <- server.Serve(listener)`, -1)
	}

	i1 := []parser.NamedTypeValue{
		parser.NewNameType("", "\"google.golang.org/grpc/health/grpc_health_v1\""),
		parser.NewNameType("kitgrpc", "\"github.com/go-kit/kit/transport/grpc\""),
		parser.NewNameType("", fmt.Sprintf("\"%s/pkg/shared_package/grpclb\"", projectPath)),
		parser.NewNameType("", fmt.Sprintf("\"%s/pkg/shared_package/grpcsr\"", projectPath)),
	}
	i2 := []parser.NamedTypeValue{}

	for _, i := range f.Imports {
		if strings.HasPrefix(i.Type, fmt.Sprintf(`"%s`, projectPath)) {
			i2 = append(i2, i)
		} else {
			i1 = append(i1, i)
		}
	}

	ni := []parser.NamedTypeValue{}
	ni = append(ni, i1...)
	ni = append(ni, parser.NewNameType("", ""))
	ni = append(ni, i2...)

	f.Imports = ni

	return defaultFs.WriteFile(sfile, f.String(), false)
}

func (cpg *ConsulPatchGenerator) generateConsulRegister() error {
	logrus.Info("Patching cmd consul...")
	te := template.NewEngine()
	defaultFs := fs.Get()

	// register
	logrus.Info("Patching cmd consul register...")
	registerPath, err := te.ExecuteString(viper.GetString("consul.register.path"), nil)
	if err != nil {
		return err
	}
	registerFileName, err := te.ExecuteString(viper.GetString("consul.register.file_name"), nil)
	if err != nil {
		return err
	}

	err = defaultFs.MkdirAll(registerPath)
	logrus.Debug(fmt.Sprintf("Creating register in shared_package: %s", registerPath))
	if err != nil {
		return err
	}

	registerstr, err := te.Execute("consul_register.go", nil)
	if err != nil {
		return err
	}

	registerfile := registerPath + defaultFs.FilePathSeparator() + registerFileName
	b, err := defaultFs.Exists(registerfile)
	if err != nil {
		return err
	}
	if b {
		logrus.Info("consul register already exists, skip re-generate")
		//return fs.NewDefaultFs(registerPath).WriteFile(registerFileName, registerstr, false)
	}

	err = defaultFs.WriteFile(registerfile, registerstr, true)
	if err != nil {
		return err
	}

	// resolver
	logrus.Info("Patching cmd consul resolver...")
	resolverPath, err := te.ExecuteString(viper.GetString("consul.resolver.path"), nil)
	if err != nil {
		return err
	}
	resolverFileName, err := te.ExecuteString(viper.GetString("consul.resolver.file_name"), nil)
	if err != nil {
		return err
	}

	err = defaultFs.MkdirAll(resolverPath)
	logrus.Debug(fmt.Sprintf("Creating resolver in shared_package: %s", resolverPath))
	if err != nil {
		return err
	}

	resolverstr, err := te.Execute("consul_resolver.go", nil)
	if err != nil {
		return err
	}

	resolverfile := resolverPath + defaultFs.FilePathSeparator() + resolverFileName
	b, err = defaultFs.Exists(resolverfile)
	if err != nil {
		return err
	}
	if b {
		logrus.Info("consul resolver already exists, skip re-generate")
		//return fs.NewDefaultFs(resolverPath).WriteFile(resolverFileName, resolverstr, false)
	}

	err = defaultFs.WriteFile(resolverfile, resolverstr, true)
	if err != nil {
		return err
	}
	return nil
}
func NewConsulPatchGenerator() *ConsulPatchGenerator {
	return &ConsulPatchGenerator{}
}
