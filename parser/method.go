package parser

import (
	"fmt"
	"go/format"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	template "github.com/kujtimiihoxha/gk/templates"
	"github.com/sirupsen/logrus"
)

type Method struct {
	Comment    string
	Name       string
	Struct     NamedTypeValue
	Body       string
	Parameters []NamedTypeValue
	Results    []NamedTypeValue
}

type CustomField struct {
	Method string
	Expose bool
	Router string
}

func NewMethod(name string, str NamedTypeValue, body string, parameters, results []NamedTypeValue) Method {
	return Method{
		Name:       name,
		Comment:    "",
		Struct:     str,
		Body:       body,
		Parameters: parameters,
		Results:    results,
	}
}

func NewMethodWithComment(name string, comment string, str NamedTypeValue, body string, parameters, results []NamedTypeValue) Method {
	m := NewMethod(name, str, body, parameters, results)
	m.Comment = prepareComments(comment)
	return m
}

func (m *Method) String() string {
	str := ""
	if m.Struct.Name != "" {
		s, err := template.NewEngine().ExecuteString("{{template \"struct_function\" .}}", m)
		if err != nil {
			logrus.Panic(err)
		}
		str = s
	} else {
		s, err := template.NewEngine().ExecuteString("{{template \"func\" .}}", m)
		if err != nil {
			logrus.Panic(err)
		}
		str = s
	}
	dt, err := format.Source([]byte(strings.TrimSpace(str)))
	if err != nil {
		fmt.Println("==========================")
		fmt.Println(string(str))
		fmt.Println("==========================")
		logrus.Panic(err)
	}
	return string(dt)
}

var myExp = regexp.MustCompile(`(method=(?P<method>\w+))?,?(expose=(?P<expose>\w+))?,?(router=(?P<router>[a-zA-Z:/]+))?`)

func (m *Method) GetCustomField() (c CustomField) {
	c.Method = http.MethodPost
	c.Expose = true
	if m.Comment == "" {
		return
	}

	match := myExp.FindAllStringSubmatch(m.Comment, -1)
	result := make(map[string]string)
	for i, name := range myExp.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[4][i]
		}
	}

	b, err := strconv.ParseBool(result["expose"])
	if err != nil {
		c.Expose = true
	} else {
		c.Expose = b
	}

	if result["method"] != "" {
		c.Method = result["method"]
	}

	if result["router"] != "" {
		c.Router = result["router"]
	}
	return
}
