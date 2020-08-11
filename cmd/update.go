package cmd

import (
	"github.com/spf13/cobra"
)

// addCmd represents the add command
var patchCmd = &cobra.Command{
	Use:   "update",
	Aliases: []string{"u"},
	Short: "Use to update service",
}

func init() {
	RootCmd.AddCommand(patchCmd)
}