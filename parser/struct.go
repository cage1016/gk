package parser

import (
	"go/format"
	"strings"

	template "github.com/kujtimiihoxha/gk/templates"
	"github.com/kujtimiihoxha/gk/utils"
	"github.com/sirupsen/logrus"
)

type Struct struct {
	Name    string
	Comment string
	Vars    []NamedTypeValue
}

func NewStruct(name string, vars []NamedTypeValue) Struct {
	for k, v := range vars {
		vars[k].Comment = utils.ToLowerSnakeCase(v.Name)
	}
	return Struct{
		Name:    name,
		Comment: "",
		Vars:    vars,
	}
}
func NewStructWithComment(name string, comment string, vars []NamedTypeValue) Struct {
	s := NewStruct(name, vars)
	s.Comment = prepareComments(comment)
	return s
}

func (s *Struct) String() string {
	str, err := template.NewEngine().ExecuteString("{{template \"struct\" .}}", s)
	if err != nil {
		logrus.Panic(err)
	}
	dt, err := format.Source([]byte(strings.TrimSpace(str)))
	if err != nil {
		logrus.Panic(err)
	}
	return string(dt)
}
