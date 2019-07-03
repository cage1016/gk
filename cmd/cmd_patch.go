package cmd

import (
	"github.com/kujtimiihoxha/gk/generator"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// addCmd represents the add command
var cmd_patchCmd = &cobra.Command{
	Use:   "cmd",
	Short: "Use to patch exist cmd for consul service discovery",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			logrus.Error("You must provide the service name")
			return
		}
		gen := generator.NewConsulPatchGenerator()
		err := gen.Generate(args[0])
		if err != nil {
			logrus.Error(err)
			return
		}
	},
}

func init() {
	patchCmd.AddCommand(cmd_patchCmd)
}
