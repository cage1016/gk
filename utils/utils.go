package utils

import (
	"github.com/alioygur/godash"
	"github.com/codeskyblue/go-sh"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func ToUpperFirstCamelCase(s string) string {
	return strings.ToUpper(string(s[0])) + godash.ToCamelCase(s)[1:]
}
func ToLowerFirstCamelCase(s string) string {
	return strings.ToLower(string(s[0])) + godash.ToCamelCase(s)[1:]
}
func ToUpperFirst(s string) string {
	return strings.ToUpper(string(s[0])) + s[1:]
}
func ToLowerSnakeCase(s string) string {
	return strings.ToLower(godash.ToSnakeCase(s))
}

func ToCamelCase(s string) string {
	return godash.ToCamelCase(s)
}

func GetModPackage() string {
	o, err := sh.Command("go", "mod", "edit", "-json").
		Command("grep", "-o", `"Path": "[^"]*`).
		Command("grep", "-o", `[^\"]*$`).
		Command("awk", "{print $1; exit}").
		Command("awk", `{printf "%s", $0}`).Output()
	if err != nil {
		return ""
	} else {
		return string(o)
	}
}

func GetGOPATH() string {
	if viper.GetString("GOPATH") != "" {
		return viper.GetString("GOPATH")
	}
	return defaultGOPATH()
}
func defaultGOPATH() string {
	env := "HOME"
	if runtime.GOOS == "windows" {
		env = "USERPROFILE"
	} else if runtime.GOOS == "plan9" {
		env = "home"
	}
	if home := os.Getenv(env); home != "" {
		def := filepath.Join(home, "go")
		if filepath.Clean(def) == filepath.Clean(runtime.GOROOT()) {
			// Don't set the default GOPATH to GOROOT,
			// as that will trigger warnings from the go tool.
			return ""
		}
		return def
	}
	return ""
}
