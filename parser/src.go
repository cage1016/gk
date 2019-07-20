package parser

import (
	"strings"
)

type ParsedSrc interface {
	String() string
}

type NamedTypeValue struct {
	Name     string
	Type     string
	Value    string
	HasValue bool
	Comment  string
}

func NewNameType(name string, tp string) NamedTypeValue {
	return NamedTypeValue{
		Name:     name,
		Type:     tp,
		HasValue: false,
	}
}

func NewNameTypeWithCommment(name string, tp string, comment string) NamedTypeValue {
	return NamedTypeValue{
		Name:     name,
		Type:     tp,
		HasValue: false,
		Comment:  comment,
	}
}

func NewNameTypeValue(name string, tp string, vl string) NamedTypeValue {
	return NamedTypeValue{
		Name:     name,
		Type:     tp,
		HasValue: true,
		Value:    vl,
	}
}

func NewNameTypeValueWithComment(name string, tp string, vl string, comment string) NamedTypeValue {
	return NamedTypeValue{
		Name:     name,
		Type:     tp,
		HasValue: true,
		Value:    vl,
		Comment:  comment,
	}
}

func prepareComments(comment string) string {
	commentList := strings.Split(comment, "\n")
	comment = ""
	for _, v := range commentList {
		comment += "// " + strings.TrimSpace(v) + "\n"
	}
	return comment
}
