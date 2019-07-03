package parser

import (
	"go/format"
	"strings"

	template "github.com/kujtimiihoxha/gk/templates"
	"github.com/sirupsen/logrus"
)

type Interface struct {
	Name    string
	Comment string
	Methods []Method
}

func NewInterface(name string, methods []Method) Interface {
	return Interface{
		Name:    name,
		Comment: "",
		Methods: methods,
	}
}
func NewInterfaceWithComment(name string, comment string, methods []Method) Interface {
	i := NewInterface(name, methods)
	i.Comment = prepareComments(comment)
	return i
}

func (i *Interface) String() string {
	str, err := template.NewEngine().ExecuteString("{{template \"interface\" .}}", i)
	if err != nil {
		logrus.Panic(err)
	}
	dt, err := format.Source([]byte(strings.TrimSpace(str)))
	if err != nil {
		logrus.Panic(err)
	}
	return string(dt)
}
