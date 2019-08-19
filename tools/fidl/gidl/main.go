// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	fidlir "fidl/compiler/backend/types"
	gidlcpp "gidl/cpp"
	gidldart "gidl/dart"
	gidlgolang "gidl/golang"
	gidlir "gidl/ir"
	gidlparser "gidl/parser"
)

// GIDLFlags for GIDL backends.
//
// --json <path>  path to the JSON IR
// --gidl <path>  path to the GIDL file
// --language (go|cpp)  language to output
type GIDLFlags struct {
	JSONPath *string
	GIDLPath *string
	Language *string
}

// Valid indicates whether the parsed Flags are valid to be used.
func (flags GIDLFlags) Valid() bool {
	return len(*flags.JSONPath) != 0 && len(*flags.GIDLPath) != 0
}

var flags = func() GIDLFlags {
	return GIDLFlags{
		JSONPath: flag.String("json", "",
			"relative path to the FIDL intermediate representation."),
		GIDLPath: flag.String("gidl", "",
			"relative path to the GIDL source."),
		Language: flag.String("language", "", "target language (go/cpp)"),
	}
}()

func parseGidlIr(filename string) gidlir.All {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	result, err := gidlparser.NewParser(filename, f).Parse()
	if err != nil {
		panic(err)
	}
	return result
}

func parseFidlJSONIr(filename string) fidlir.Root {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	var result fidlir.Root
	if err := json.Unmarshal(bytes, &result); err != nil {
		panic(err)
	}
	return result
}

func filterByBinding(input gidlir.All, binding string) gidlir.All {
	var output gidlir.All
	for _, def := range input.Success {
		if shouldKeep(binding, def.BindingsAllowlist, def.BindingsDenylist) {
			output.Success = append(output.Success, def)
		}
	}
	for _, def := range input.EncodeSuccess {
		if shouldKeep(binding, def.BindingsAllowlist, def.BindingsDenylist) {
			output.EncodeSuccess = append(output.EncodeSuccess, def)
		}
	}
	for _, def := range input.DecodeSuccess {
		if shouldKeep(binding, def.BindingsAllowlist, def.BindingsDenylist) {
			output.DecodeSuccess = append(output.DecodeSuccess, def)
		}
	}
	for _, def := range input.EncodeFailure {
		if shouldKeep(binding, def.BindingsAllowlist, def.BindingsDenylist) {
			output.EncodeFailure = append(output.EncodeFailure, def)
		}
	}
	for _, def := range input.DecodeFailure {
		if shouldKeep(binding, def.BindingsAllowlist, def.BindingsDenylist) {
			output.DecodeFailure = append(output.DecodeFailure, def)
		}
	}
	return output
}

func shouldKeep(binding string, allowlist *[]string, denylist *[]string) bool {
	if denylist != nil {
		for _, item := range *denylist {
			if binding == item {
				return false
			}
		}
	}
	if allowlist != nil {
		for _, item := range *allowlist {
			if binding == item {
				return true
			}
		}
		return false
	}
	return true
}

func main() {
	flag.Parse()

	if !flag.Parsed() || !flags.Valid() {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Parse GIDL and JSON IR.
	var (
		gidl = filterByBinding(parseGidlIr(*flags.GIDLPath), *flags.Language)
		fidl = parseFidlJSONIr(*flags.JSONPath)
	)

	// For simplicity, we do not allow FIDL that GIDL depends on to have
	// dependent libraries. This makes it much simpler to have everything
	// in the IR, and avoid cross-references.
	if len(fidl.Libraries) != 0 {
		var libs []string
		for _, l := range fidl.Libraries {
			libs = append(libs, string(l.Name))
		}
		panic(fmt.Sprintf(
			"GIDL does not work with FIDL libraries with dependents, found: %s",
			strings.Join(libs, ",")))
	}

	buf := new(bytes.Buffer)

	switch language := *flags.Language; language {
	case "go":
		err := gidlgolang.Generate(buf, gidl, fidl)
		if err != nil {
			panic(err)
		}
	case "cpp":
		err := gidlcpp.Generate(buf, gidl, fidl)
		if err != nil {
			panic(err)
		}
	case "dart":
		err := gidldart.Generate(buf, gidl, fidl)
		if err != nil {
			panic(err)
		}
	case "":
		panic("must specify --language")
	default:
		panic(fmt.Sprintf("unknown language: %s", language))
	}

	_, err := os.Stdout.Write(buf.Bytes())
	if err != nil {
		panic(err)
	}
}
