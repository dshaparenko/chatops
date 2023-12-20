package cmd

import (
	"fmt"
	"os"
	"os/signal"
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

var VERSION = "unknown"
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
	Prefix: envGet("PROMETHEUS_METRICS_PREFIX", "").(string),
}

var telegramOptions = bot.TelegramOptions{
	BotToken: envGet("TELEGRAM_BOT_TOKEN", "").(string),
	Debug:    envGet("TELEGRAM_DEBUG", false).(bool),
	Timeout:  envGet("TELEGRAM_TIMEOUT", 60).(int),
	Offset:   envGet("TELEGRAM_OFFSET", 0).(int),
}

var slackOptions = bot.SlackOptions{
	BotToken:      envGet("SLACK_BOT_TOKEN", "").(string),
	AppToken:      envGet("SLACK_APP_TOKEN", "").(string),
	Debug:         envGet("SLACK_DEBUG", false).(bool),
	ReplyInThread: envGet("SLACK_REPLY_IN_THREAD", false).(bool),
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

			stdoutOptions.Version = VERSION
			stdout = sreProvider.NewStdout(stdoutOptions)
			if utils.Contains(rootOptions.Logs, "stdout") && stdout != nil {
				stdout.SetCallerOffset(2)
				logs.Register(stdout)
			}

			logs.Info("Booting...")

			// Metrics

			prometheusOptions.Version = VERSION
			prometheus := sreProvider.NewPrometheusMeter(prometheusOptions, logs, stdout)
			if utils.Contains(rootOptions.Metrics, "prometheus") && prometheus != nil {
				prometheus.StartInWaitGroup(&mainWG)
				metrics.Register(prometheus)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {

			obs := common.NewObservability(logs, metrics)
			processors := common.NewProcessors()
			processors.Add(processor.NewStart(startOptions, obs, processors))
			//processors.Add(processor.NewK8s(k8sOptions, obs))
			//processors.Add(processor.NewGrafana(grafanaOptions, obs))

			bots := common.NewBots()
			bots.Add(bot.NewTelegram(telegramOptions, obs, processors))
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

	SetStartFlags(flags)
	SetK8sFlags(flags)
	SetGrafanaFlags(flags)

	interceptSyscall()

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(VERSION)
		},
	})

	if err := rootCmd.Execute(); err != nil {
		logs.Error(err)
		os.Exit(1)
	}
}
