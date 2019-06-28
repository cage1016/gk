package cmd

import (
	"github.com/spf13/cobra"
)

var newCmd = &cobra.Command{
	Use:     "new",
	Aliases: []string{"n"},
	Short:   "A set of generators used to create new cmd/services/transports/middlewares",
}

func init() {
	RootCmd.AddCommand(newCmd)
}
