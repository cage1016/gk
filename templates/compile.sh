#!/usr/bin/env bash
go-bindata -pkg=template  -ignore=template.go -nomemcopy  tmpl/...