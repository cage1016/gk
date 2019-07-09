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
		if !strings.Contains(f.Methods[2].Body, `consulAddres := fmt.Sprintf("%s:%s", cfg.consulHost, cfg.consultPort)`) {
			f.Methods[2].Body = strings.Replace(
				string(f.Methods[2].Body),
				"cfg := loadConfig(logger)",
				`cfg := loadConfig(logger)
	
				consulAddres := fmt.Sprintf("%s:%s", cfg.consulHost, cfg.consultPort)
				serviceIp := localIP()
				servicePort, _ := strconv.Atoi(cfg.grpcPort)
				consulReg := consulregister.NewConsulRegister(consulAddres, cfg.serviceName, serviceIp, servicePort, []string{cfg.nameSpace, cfg.serviceName}, logger)
				svcRegistar, err := consulReg.NewConsulGRPCRegister()
				defer svcRegistar.Deregister()
				if err != nil {
					level.Error(logger).Log(
						"consulAddres", consulAddres,
						"serviceName", cfg.serviceName,
						"serviceIp", serviceIp,
						"servicePort", servicePort,
						"tags", []string{cfg.nameSpace, cfg.serviceName},
						"err", err,
					)
				}`,
				-1,
			)
			f.Methods[2].Body = strings.Replace(f.Methods[2].Body,
				"go startGRPCServer(cfg, grpcServer, logger, errs)",
				"go startGRPCServer(cfg, svcRegistar, grpcServer, logger, errs)", -1)
			f.Methods[2].Body = strings.Replace(f.Methods[2].Body, "err := <-errs", "err = <-errs", -1)
		} else {
			logrus.Info("consul has been patched. skip action")
			return nil
		}
	}

	// New Server
	{
		for i, _ := range f.Methods[4].Results {
			f.Methods[4].Results[i].Name = ""
		}
	}

	// startGRPCServer parameters
	{
		rear := append([]parser.NamedTypeValue{}, f.Methods[6].Parameters[1:]...)
		ss := append(f.Methods[6].Parameters[0:1], parser.NewNameType("registar", "sd.Registrar"))
		ss = append(ss, rear...)
		f.Methods[6].Parameters = ss

		f.Methods[6].Body = strings.Replace(f.Methods[6].Body, "errs <- server.Serve(listener)",
			`grpc_health_v1.RegisterHealthServer(server, &service.HealthImpl{})
					registar.Register()
					errs <- server.Serve(listener)`, -1)
	}

	i1 := []parser.NamedTypeValue{
		parser.NewNameType("", "\"google.golang.org/grpc/health/grpc_health_v1\""),
		parser.NewNameType("kitgrpc", "\"github.com/go-kit/kit/transport/grpc\""),
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
	logrus.Info("Patching cmd consul register...")
	te := template.NewEngine()
	defaultFs := fs.Get()

	crs, err := te.Execute("consulregister.go", nil)
	if err != nil {
		return err
	}

	cname, err := te.ExecuteString(viper.GetString("consulregister.file_name"), nil)
	cpath, err := te.ExecuteString(viper.GetString("consulregister.path"), nil)
	b, err := defaultFs.Exists(cpath)
	if err != nil {
		return err
	}
	if b {
		logrus.Info("consulregister already exists")
		return fs.NewDefaultFs(cpath).WriteFile(cname, crs, false)
	}

	err = defaultFs.MkdirAll(cpath)
	logrus.Debug(fmt.Sprintf("Creating consulregister pkg : %s", cpath))
	if err != nil {
		return err
	}

	crfile := cpath + defaultFs.FilePathSeparator() + cname
	err = defaultFs.WriteFile(crfile, crs, true)
	if err != nil {
		return err
	}
	return nil
}
func NewConsulPatchGenerator() *ConsulPatchGenerator {
	return &ConsulPatchGenerator{}
}
