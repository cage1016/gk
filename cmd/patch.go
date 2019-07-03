package cmd

import (
	"github.com/spf13/cobra"
)

// addCmd represents the add command
var patchCmd = &cobra.Command{
	Use:   "patch",
	Short: "Use to patch exist service for consul service discovery",
}

func init() {
	RootCmd.AddCommand(patchCmd)
}