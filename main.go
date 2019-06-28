package main

import (
	"fmt"
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

	modPage := utils.GetModPackage()
	if modPage == "" {
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
	} else {
		fmt.Println(fmt.Sprintf("Go mod package: %s", modPage))
	}
	cmd.Execute()
}
