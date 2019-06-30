package cmd

import (
	"github.com/kujtimiihoxha/gk/generator"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// addCmd represents the add command
var patchCmd = &cobra.Command{
	Use:   "patch",
	Short: "Use to patch exist service for adding middleware",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			logrus.Error("You must provide the service name")
			return
		}
		gen := generator.NewServicePatchGenerator()
		err := gen.Generator(args[0])
		if err != nil {
			logrus.Error(err)
			return
		}
	},
}

func init() {
	RootCmd.AddCommand(patchCmd)
}
