package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/kujtimiihoxha/gk/generator"
	"github.com/spf13/cobra"
)

// serviceCmd represents the service command
var middlewareCmd = &cobra.Command{
	Use:     "middleware",
	Short:   "Create the skeleton of a middleware",
	Aliases: []string{"m", "md"},
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			logrus.Error("You must provide a name for the service")
			return
		}
		gen := generator.NewMiddlewareGenerator()
		err := gen.Generate(args[0])
		if err != nil {
			logrus.Error(err)
		}
	},
}

func init() {
	newCmd.AddCommand(middlewareCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// serviceCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// serviceCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
