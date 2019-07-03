package main

import (
	"os"
	"strings"

	"github.com/kujtimiihoxha/gk/cmd"
	"github.com/kujtimiihoxha/gk/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"github.com/spf13/viper"
)

func main() {
	viper.AutomaticEnv()

	modPackage := utils.GetModPackage()
	if modPackage == "" {
		logrus.Info("Go Mod package does not exist. check GOPATH ")
		gosrc := utils.GetGOPATH() + afero.FilePathSeparator + "src" + afero.FilePathSeparator
		pwd, err := os.Getwd()
		if err != nil {
			logrus.Error(err)
			return
		}
		if !strings.HasPrefix(pwd, gosrc) {
			logrus.Error("The project must be in the $GOPATH/src folder for the generator to work.")
			return
		}
	}
	cmd.Execute()
}
