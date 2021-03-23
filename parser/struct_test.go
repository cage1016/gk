package parser

import (
	"fmt"
	"testing"
)

func Test_NewStruct(t *testing.T) {
	s := NewStruct("config", []NamedTypeValue{})
	s.Name = "Config"
	vars := []NamedTypeValue{
		NewNameTypeValueWithComment("a", "string", "1", "2"),
		NewNameType("ServiceName", "string"),
		NewNameType("LogLevel", "string"),
		NewNameType("ServiceHost", "string"),
		NewNameType("HttpPort", "string"),
		NewNameType("GrpcPort", "string"),
		NewNameType("ZipkinV2URL", "string"),
		NewNameType("JaegerURL", "string"),
	}
	s.Vars = append(s.Vars, vars...)

	fmt.Println(s.String())
}

func Test_NewStructWithComment(t *testing.T) {
	s := NewStructWithComment("config", "this is comment", []NamedTypeValue{})
	s.Name = "Config"
	vars := []NamedTypeValue{
		NewNameTypeValueWithTags("ServiceName", "string", "", `envconfig:"QS_SERVICE_NAME" default:"add"`),
		NewNameTypeValueWithTags("ServiceHost", "string", "", `envconfig:"QS_SERVICE_HOST" default:"localhost"`),
		NewNameTypeValueWithTags("LogLevel", "string", "", `envconfig:"QS_LOG_LEVEL" default:"error"`),
		NewNameTypeValueWithTags("HttpPort", "string", "", `envconfig:"QS_HTTP_PORT" default:"8180"`),
		NewNameTypeValueWithTags("GrpcPort", "string", "", `envconfig:"QS_GRPC_PORT" default:"8181"`),
		NewNameTypeValueWithTags("ZipkinV2URL", "string", "", `envconfig:"QS_ZIPKIN_V2_URL"`),
		NewNameTypeValueWithTags("JaegerURL", "string", "", `envconfig:"QS_JAEGER_URL"`),
	}
	s.Vars = append(s.Vars, vars...)

	fmt.Println(s.String())
}
