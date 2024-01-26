package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"sync"
	"syscall"

	"github.com/devopsext/chatops/bot"
	"github.com/devopsext/chatops/common"
	"github.com/devopsext/chatops/processor"

	sreCommon "github.com/devopsext/sre/common"
	sreProvider "github.com/devopsext/sre/provider"
	utils "github.com/devopsext/utils"
	"github.com/spf13/cobra"
)

var version = "unknown"
var APPNAME = "CHATOPS"
var appName = strings.ToLower(APPNAME)

var logs = sreCommon.NewLogs()
var metrics = sreCommon.NewMetrics()
var stdout *sreProvider.Stdout
var mainWG sync.WaitGroup

type RootOptions struct {
	Logs    []string
	Metrics []string
}

var rootOptions = RootOptions{
	Logs:    strings.Split(envGet("LOGS", "stdout").(string), ","),
	Metrics: strings.Split(envGet("METRICS", "prometheus").(string), ","),
}

var stdoutOptions = sreProvider.StdoutOptions{
	Format:          envGet("STDOUT_FORMAT", "text").(string),
	Level:           envGet("STDOUT_LEVEL", "info").(string),
	Template:        envGet("STDOUT_TEMPLATE", "{{.file}} {{.msg}}").(string),
	TimestampFormat: envGet("STDOUT_TIMESTAMP_FORMAT", time.RFC3339Nano).(string),
	TextColors:      envGet("STDOUT_TEXT_COLORS", true).(bool),
}

var prometheusOptions = sreProvider.PrometheusOptions{
	URL:    envGet("PROMETHEUS_METRICS_URL", "/metrics").(string),
	Listen: envGet("PROMETHEUS_METRICS_LISTEN", "127.0.0.1:8080").(string),
	Prefix: envGet("PROMETHEUS_METRICS_PREFIX", "chatops").(string),
}

var telegramOptions = bot.TelegramOptions{
	BotToken: envGet("TELEGRAM_BOT_TOKEN", "").(string),
	Debug:    envGet("TELEGRAM_DEBUG", false).(bool),
	Timeout:  envGet("TELEGRAM_TIMEOUT", 60).(int),
	Offset:   envGet("TELEGRAM_OFFSET", 0).(int),
}

var slackOptions = bot.SlackOptions{
	BotToken:       envGet("SLACK_BOT_TOKEN", "").(string),
	AppToken:       envGet("SLACK_APP_TOKEN", "").(string),
	Debug:          envGet("SLACK_DEBUG", false).(bool),
	ReplyInThread:  envGet("SLACK_REPLY_IN_THREAD", false).(bool),
	ReactionDoing:  envGet("SLACK_REACTION_DOING", "eyes").(string),
	ReactionDone:   envGet("SLACK_REACTION_DONE", "white_check_mark").(string),
	ReactionFailed: envGet("SLACK_REACTION_FAILED", "x").(string),
	DefaultCommand: envGet("SLACK_DEFAULT_COMMAND", "").(string),
	HelpCommand:    envGet("SLACK_HELP_COMMAND", "").(string),
	Permisssions:   envGet("SLACK_PERMISSIONS", "").(string),
}

var defaultOptions = processor.DefaultOptions{
	CommandsDir: envGet("DEFAULT_COMMANDS_DIR", "").(string),
	CommandExt:  envGet("DEFAULT_COMMAND_EXT", ".tpl").(string),
	ConfigExt:   envGet("DEFAULT_CONFIG_EXT", ".yml").(string),
	Error:       envGet("DEFAULT_ERROR", "Couldn't execute command").(string),
}

func getOnlyEnv(key string) string {
	value, ok := os.LookupEnv(key)
	if ok {
		return value
	}
	return fmt.Sprintf("$%s", key)
}

func envGet(s string, def interface{}) interface{} {
	return utils.EnvGet(fmt.Sprintf("%s_%s", APPNAME, s), def)
}

func envStringExpand(s string, def string) string {
	snew := envGet(s, def).(string)
	return os.Expand(snew, getOnlyEnv)
}

func envFileContentExpand(s string, def string) string {
	snew := envGet(s, def).(string)
	bytes, err := utils.Content(snew)
	if err != nil {
		return def
	}
	return os.Expand(string(bytes), getOnlyEnv)
}

func interceptSyscall() {

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-c
		logs.Info("Exiting...")
		os.Exit(1)
	}()
}

func buildDefaultProcessors(options processor.DefaultOptions, obs *common.Observability, processors *common.Processors) error {

	logger := obs.Logs()
	first, err := os.ReadDir(options.CommandsDir)
	if err != nil {
		logger.Error("Couldn't read default dir %s, error %s", options.CommandsDir, err)
		return err
	}

	commandExt := defaultOptions.CommandExt
	if utils.IsEmpty(commandExt) {
		commandExt = ".tpl"
	}

	configExt := defaultOptions.ConfigExt
	if utils.IsEmpty(configExt) {
		configExt = ".yml"
	}

	// scan dirs firstly
	for _, de1 := range first {

		name1 := de1.Name()
		path1 := fmt.Sprintf("%s%c%s", options.CommandsDir, os.PathSeparator, name1)

		// dir is there
		if de1.IsDir() {
			second, err := os.ReadDir(path1)
			if err != nil {
				logger.Error("Couldn't read default dir %s, error %s", options.CommandsDir, err)
				return err
			}

			dirProcessor := processor.NewDefault(name1, options, obs, processors)
			if utils.IsEmpty(dirProcessor) {
				logger.Error("No default dir processor %s", name1)
				return err
			}

			for _, de2 := range second {

				name2 := de2.Name()
				path2 := fmt.Sprintf("%s%c%s", path1, os.PathSeparator, name2)
				if de2.IsDir() {
					continue
				}
				ext := filepath.Ext(name2)
				if ext != commandExt {
					continue
				}

				err := dirProcessor.AddCommand(strings.TrimSuffix(name2, ext), path2)
				if err != nil {
					return err
				}
			}
			processors.Add(dirProcessor)
		}
	}

	rootProcessor := processor.NewDefault("", options, obs, processors)
	if utils.IsEmpty(rootProcessor) {
		logger.Error("No default root processor")
		return err
	}
	processors.Add(rootProcessor)

	// scan files secondly
	for _, de1 := range first {

		name1 := de1.Name()
		path1 := fmt.Sprintf("%s%c%s", options.CommandsDir, os.PathSeparator, name1)

		// file is there
		if !de1.IsDir() {
			ext := filepath.Ext(name1)
			if ext != commandExt {
				continue
			}
			err := rootProcessor.AddCommand(strings.TrimSuffix(name1, ext), path1)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// /start - show list of commands and simple description
// /k8s - list of k8s clusters
// /k8s/cluster1 - type k8s cluster
// /k8s/cluster2 - type k8s cluster
// /grafana - current grafana
// /aws/name-of-resource - some resource under aws
// /alicloud - whole alicloud account
// /some-command - custom command
// /gitlab?
// /datadog
// /newrelic

func Execute() {

	rootCmd := &cobra.Command{
		Use:   "chatops",
		Short: "Chatops",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {

			stdoutOptions.Version = version
			stdout = sreProvider.NewStdout(stdoutOptions)
			if utils.Contains(rootOptions.Logs, "stdout") && stdout != nil {
				stdout.SetCallerOffset(2)
				logs.Register(stdout)
			}

			logs.Info("Booting...")

			// Metrics

			prometheusOptions.Version = version
			prometheus := sreProvider.NewPrometheusMeter(prometheusOptions, logs, stdout)
			if utils.Contains(rootOptions.Metrics, "prometheus") && prometheus != nil {
				prometheus.StartInWaitGroup(&mainWG)
				metrics.Register(prometheus)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {

			obs := common.NewObservability(logs, metrics)
			processors := common.NewProcessors()

			err := buildDefaultProcessors(defaultOptions, obs, processors)
			if err != nil {
				os.Exit(1)
			}

			bots := common.NewBots()
			//bots.Add(bot.NewTelegram(telegramOptions, obs, processors))
			bots.Add(bot.NewSlack(slackOptions, obs, processors))

			bots.Start(&mainWG)
			mainWG.Wait()
		},
	}

	flags := rootCmd.PersistentFlags()

	flags.StringSliceVar(&rootOptions.Logs, "logs", rootOptions.Logs, "Log providers: stdout")
	flags.StringSliceVar(&rootOptions.Metrics, "metrics", rootOptions.Metrics, "Metric providers: prometheus")

	flags.StringVar(&stdoutOptions.Format, "stdout-format", stdoutOptions.Format, "Stdout format: json, text, template")
	flags.StringVar(&stdoutOptions.Level, "stdout-level", stdoutOptions.Level, "Stdout level: info, warn, error, debug, panic")
	flags.StringVar(&stdoutOptions.Template, "stdout-template", stdoutOptions.Template, "Stdout template")
	flags.StringVar(&stdoutOptions.TimestampFormat, "stdout-timestamp-format", stdoutOptions.TimestampFormat, "Stdout timestamp format")
	flags.BoolVar(&stdoutOptions.TextColors, "stdout-text-colors", stdoutOptions.TextColors, "Stdout text colors")
	flags.BoolVar(&stdoutOptions.Debug, "stdout-debug", stdoutOptions.Debug, "Stdout debug")

	flags.StringVar(&prometheusOptions.URL, "prometheus-url", prometheusOptions.URL, "Prometheus endpoint url")
	flags.StringVar(&prometheusOptions.Listen, "prometheus-listen", prometheusOptions.Listen, "Prometheus listen")
	flags.StringVar(&prometheusOptions.Prefix, "prometheus-prefix", prometheusOptions.Prefix, "Prometheus prefix")

	flags.StringVar(&telegramOptions.BotToken, "telegram-bot-token", telegramOptions.BotToken, "Telegram bot token")
	flags.BoolVar(&telegramOptions.Debug, "telegram-debug", telegramOptions.Debug, "Telegram debug")
	flags.IntVar(&telegramOptions.Timeout, "telegram-timeout", telegramOptions.Timeout, "Telegram timeout")

	flags.StringVar(&slackOptions.BotToken, "slack-bot-token", slackOptions.BotToken, "Slack bot token")
	flags.StringVar(&slackOptions.AppToken, "slack-app-token", slackOptions.AppToken, "Slack app token")
	flags.BoolVar(&slackOptions.Debug, "slack-debug", slackOptions.Debug, "Slack debug")
	flags.BoolVar(&slackOptions.ReplyInThread, "slack-reply-in-thread", slackOptions.ReplyInThread, "Slack reply in thread")
	flags.StringVar(&slackOptions.ReactionDoing, "slack-reaction-doing", slackOptions.ReactionDoing, "Slack reaction doing name")
	flags.StringVar(&slackOptions.ReactionDone, "slack-reaction-done", slackOptions.ReactionDone, "Slack reaction done name")
	flags.StringVar(&slackOptions.ReactionFailed, "slack-reaction-failed", slackOptions.ReactionFailed, "Slack reaction failed name")
	flags.StringVar(&slackOptions.DefaultCommand, "slack-default-command", slackOptions.DefaultCommand, "Slack default command")
	flags.StringVar(&slackOptions.HelpCommand, "slack-help-command", slackOptions.HelpCommand, "Slack help command")
	flags.StringVar(&slackOptions.Permisssions, "slack-permissions", slackOptions.Permisssions, "Slack permissions")

	flags.StringVar(&defaultOptions.CommandsDir, "default-commands-dir", defaultOptions.CommandsDir, "Default commands directory")
	flags.StringVar(&defaultOptions.CommandExt, "default-command-ext", defaultOptions.CommandExt, "Default command extension")
	flags.StringVar(&defaultOptions.ConfigExt, "default-config-ext", defaultOptions.ConfigExt, "Default config extension")
	flags.StringVar(&defaultOptions.Error, "default-error", defaultOptions.Error, "Default error")

	interceptSyscall()

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	})

	if err := rootCmd.Execute(); err != nil {
		logs.Error(err)
		os.Exit(1)
	}
}
