// Command lwauthctl is a small operator CLI for inspecting config,
// listing registered modules, and dry-running an authorization request
// against a local config file.
//
// M0 ships only the `modules` and `validate` subcommands.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	_ "github.com/mikeappsec/lightweightauth/pkg/builtins"

	"github.com/mikeappsec/lightweightauth/internal/config"
	"github.com/mikeappsec/lightweightauth/pkg/module"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "modules":
		listModules()
	case "validate":
		validate(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lwauthctl <modules|validate> [args]")
	os.Exit(2)
}

func listModules() {
	for _, k := range []module.Kind{module.KindIdentifier, module.KindAuthorizer, module.KindMutator} {
		names := module.RegisteredTypes(k)
		sort.Strings(names)
		fmt.Printf("%s:\n", k)
		for _, n := range names {
			fmt.Printf("  - %s\n", n)
		}
	}
}

func validate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to AuthConfig YAML")
	_ = fs.Parse(args)
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "--config required")
		os.Exit(2)
	}
	ac, err := config.LoadFile(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	if _, err := config.Compile(ac); err != nil {
		fmt.Fprintln(os.Stderr, "compile:", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}
