package cmd

import (
	"github.com/devopsext/chatops/processor"
	"github.com/spf13/pflag"
)

var defaultOptions = processor.DefaultOptions{
	Dir:     envGet("DEFAULT_DIR", "").(string),
	Pattern: envGet("DEFAULT_PATTERN", "*.template").(string),
}

func SetDefaultFlags(flags *pflag.FlagSet) {
	flags.StringVar(&defaultOptions.Dir, "default-dir", defaultOptions.Dir, "Default dir")
	flags.StringVar(&defaultOptions.Pattern, "default-pattern", defaultOptions.Pattern, "Default pattern")
}
