package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/asuhacoder/handkey/internal/cli"
)

var version = "dev"

func main() { os.Exit(run()) }
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "version" {
		fmt.Fprintln(os.Stdout, "handkey", version)
		return 0
	}
	if len(args) > 0 && args[0] == "serve" {
		if e := cli.Serve(ctx, args[1:], os.Stdout, os.Stderr); e != nil {
			fmt.Fprintln(os.Stderr, "handkey:", e)
			return 1
		}
		return 0
	}
	cwd, e := os.Getwd()
	if e != nil {
		fmt.Fprintln(os.Stderr, "handkey: working directory unavailable")
		return 1
	}
	return (cli.Runner{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, Env: os.Environ(), Cwd: cwd}).Run(ctx, args)
}
