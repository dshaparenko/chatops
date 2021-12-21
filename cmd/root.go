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

	sreCommon "github.com/devopsext/sre/common"
	sreProvider "github.com/devopsext/sre/provider"
	utils "github.com/devopsext/utils"
	"github.com/spf13/cobra"
)

var VERSION = "unknown"
var APPNAME = "CHATOPS"
var appName = strings.ToLower(APPNAME)

var env = utils.GetEnvironment()
var logs = sreCommon.NewLogs()
var metrics = sreCommon.NewMetrics()
var traces = sreCommon.NewTraces()
var stdout *sreProvider.Stdout
var mainWG sync.WaitGroup

type RootOptions struct {
	Logs    []string
	Metrics []string
	Traces  []string
}

var rootOptions = RootOptions{

	Logs:    strings.Split(env.Get(fmt.Sprintf("%s_LOGS", APPNAME), "stdout").(string), ","),
	Metrics: strings.Split(env.Get(fmt.Sprintf("%s_METRICS", APPNAME), "prometheus").(string), ","),
	Traces:  strings.Split(env.Get(fmt.Sprintf("%s_TRACES", APPNAME), "").(string), ","),
}

var stdoutOptions = sreProvider.StdoutOptions{

	Format:          env.Get(fmt.Sprintf("%s_STDOUT_FORMAT", APPNAME), "text").(string),
	Level:           env.Get(fmt.Sprintf("%s_STDOUT_LEVEL", APPNAME), "info").(string),
	Template:        env.Get(fmt.Sprintf("%s_STDOUT_TEMPLATE", APPNAME), "{{.file}} {{.msg}}").(string),
	TimestampFormat: env.Get(fmt.Sprintf("%s_STDOUT_TIMESTAMP_FORMAT", APPNAME), time.RFC3339Nano).(string),
	TextColors:      env.Get(fmt.Sprintf("%s_STDOUT_TEXT_COLORS", APPNAME), true).(bool),
}

var prometheusOptions = sreProvider.PrometheusOptions{

	URL:    env.Get(fmt.Sprintf("%s_PROMETHEUS_URL", APPNAME), "/metrics").(string),
	Listen: env.Get(fmt.Sprintf("%s_PROMETHEUS_LISTEN", APPNAME), "127.0.0.1:8080").(string),
	Prefix: env.Get(fmt.Sprintf("%s_PROMETHEUS_PREFIX", APPNAME), appName).(string),
}

/*var grafanaOptions = render.GrafanaOptions{

	URL:         env.Get(fmt.Sprintf("%s_GRAFANA_URL",APPNAME), "").(string),
	Timeout:     env.Get(fmt.Sprintf("%s_GRAFANA_TIMEOUT",APPNAME), 60).(int),
	Datasource:  env.Get(fmt.Sprintf("%s_GRAFANA_DATASOURCE",APPNAME), "Prometheus").(string),
	ApiKey:      env.Get(fmt.Sprintf("%s_GRAFANA_API_KEY",APPNAME), "admin:admin").(string),
	Org:         env.Get(fmt.Sprintf("%s_GRAFANA_ORG",APPNAME), "1").(string),
	Period:      env.Get(fmt.Sprintf("%s_GRAFANA_PERIOD",APPNAME), 60).(int),
	ImageWidth:  env.Get(fmt.Sprintf("%s_GRAFANA_IMAGE_WIDTH", APPNAME),1280).(int),
	ImageHeight: env.Get(fmt.Sprintf("%s_GRAFANA_IMAGE_HEIGHT",APPNAME), 640).(int),
}*/

var jaegerOptions = sreProvider.JaegerOptions{
	ServiceName:         env.Get(fmt.Sprintf("%s_JAEGER_SERVICE_NAME", APPNAME), appName).(string),
	AgentHost:           env.Get(fmt.Sprintf("%s_JAEGER_AGENT_HOST", APPNAME), "").(string),
	AgentPort:           env.Get(fmt.Sprintf("%s_JAEGER_AGENT_PORT", APPNAME), 6831).(int),
	Endpoint:            env.Get(fmt.Sprintf("%s_JAEGER_ENDPOINT", APPNAME), "").(string),
	User:                env.Get(fmt.Sprintf("%s_JAEGER_USER", APPNAME), "").(string),
	Password:            env.Get(fmt.Sprintf("%s_JAEGER_PASSWORD", APPNAME), "").(string),
	BufferFlushInterval: env.Get(fmt.Sprintf("%s_JAEGER_BUFFER_FLUSH_INTERVAL", APPNAME), 0).(int),
	QueueSize:           env.Get(fmt.Sprintf("%s_JAEGER_QUEUE_SIZE", APPNAME), 0).(int),
	Tags:                env.Get(fmt.Sprintf("%s_JAEGER_TAGS", APPNAME), "").(string),
	Debug:               env.Get(fmt.Sprintf("%s_JAEGER_DEBUG", APPNAME), false).(bool),
}

var telegramOptions = bot.TelegramOptions{
	BotToken: env.Get(fmt.Sprintf("%s_TELEGRAM_BOT_TOKEN", APPNAME), "").(string),
	Debug:    env.Get(fmt.Sprintf("%s_TELEGRAM_DEBUG", APPNAME), false).(bool),
	Timeout:  env.Get(fmt.Sprintf("%s_TELEGRAM_TIMEOUT", APPNAME), 60).(int),
	Offset:   env.Get(fmt.Sprintf("%s_TELEGRAM_OFFSET", APPNAME), 0).(int),
}

func interceptSyscall() {

	c := make(chan os.Signal)
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

			// Tracing

			jaegerOptions.Version = VERSION
			jaeger := sreProvider.NewJaegerTracer(jaegerOptions, logs, stdout)
			if utils.Contains(rootOptions.Traces, "jaeger") && jaeger != nil {
				traces.Register(jaeger)
			}

		},
		Run: func(cmd *cobra.Command, args []string) {

			bots := common.NewBots()
			observability := common.NewObservability(logs, traces, metrics)

			telegram := bot.NewTelegram(telegramOptions, observability)
			if telegram != nil {
				bots.Add(telegram)
			}

			// slack := bot.NewSlack()
			// if slack != nil {
			// 	bots.Add(slack)
			// }

			bots.StartInWaitGroup(&mainWG)
			mainWG.Wait()
		},
	}

	flags := rootCmd.PersistentFlags()

	flags.StringSliceVar(&rootOptions.Logs, "logs", rootOptions.Logs, "Log providers: stdout")
	flags.StringSliceVar(&rootOptions.Metrics, "metrics", rootOptions.Metrics, "Metric providers: prometheus")
	flags.StringSliceVar(&rootOptions.Traces, "traces", rootOptions.Traces, "Trace providers: jaeger")

	flags.StringVar(&stdoutOptions.Format, "stdout-format", stdoutOptions.Format, "Stdout format: json, text, template")
	flags.StringVar(&stdoutOptions.Level, "stdout-level", stdoutOptions.Level, "Stdout level: info, warn, error, debug, panic")
	flags.StringVar(&stdoutOptions.Template, "stdout-template", stdoutOptions.Template, "Stdout template")
	flags.StringVar(&stdoutOptions.TimestampFormat, "stdout-timestamp-format", stdoutOptions.TimestampFormat, "Stdout timestamp format")
	flags.BoolVar(&stdoutOptions.TextColors, "stdout-text-colors", stdoutOptions.TextColors, "Stdout text colors")
	flags.BoolVar(&stdoutOptions.Debug, "stdout-debug", stdoutOptions.Debug, "Stdout debug")

	flags.StringVar(&prometheusOptions.URL, "prometheus-url", prometheusOptions.URL, "Prometheus endpoint url")
	flags.StringVar(&prometheusOptions.Listen, "prometheus-listen", prometheusOptions.Listen, "Prometheus listen")
	flags.StringVar(&prometheusOptions.Prefix, "prometheus-prefix", prometheusOptions.Prefix, "Prometheus prefix")

	/*flags.StringVar(&grafanaOptions.URL, "grafana-url", grafanaOptions.URL, "Grafana URL")
	flags.IntVar(&grafanaOptions.Timeout, "grafana-timeout", grafanaOptions.Timeout, "Grafan timeout")
	flags.StringVar(&grafanaOptions.Datasource, "grafana-datasource", grafanaOptions.Datasource, "Grafana datasource")
	flags.StringVar(&grafanaOptions.ApiKey, "grafana-api-key", grafanaOptions.ApiKey, "Grafana API key")
	flags.StringVar(&grafanaOptions.Org, "grafana-org", grafanaOptions.Org, "Grafana org")
	flags.IntVar(&grafanaOptions.Period, "grafana-period", grafanaOptions.Period, "Grafana period in minutes")
	flags.IntVar(&grafanaOptions.ImageWidth, "grafana-image-width", grafanaOptions.ImageWidth, "Grafan image width")
	flags.IntVar(&grafanaOptions.ImageHeight, "grafana-image-height", grafanaOptions.ImageHeight, "Grafan image height")
	*/
	flags.StringVar(&jaegerOptions.ServiceName, "jaeger-service-name", jaegerOptions.ServiceName, "Jaeger service name")
	flags.StringVar(&jaegerOptions.AgentHost, "jaeger-agent-host", jaegerOptions.AgentHost, "Jaeger agent host")
	flags.IntVar(&jaegerOptions.AgentPort, "jaeger-agent-port", jaegerOptions.AgentPort, "Jaeger agent port")
	flags.StringVar(&jaegerOptions.Endpoint, "jaeger-endpoint", jaegerOptions.Endpoint, "Jaeger endpoint")
	flags.StringVar(&jaegerOptions.User, "jaeger-user", jaegerOptions.User, "Jaeger user")
	flags.StringVar(&jaegerOptions.Password, "jaeger-password", jaegerOptions.Password, "Jaeger password")
	flags.IntVar(&jaegerOptions.BufferFlushInterval, "jaeger-buffer-flush-interval", jaegerOptions.BufferFlushInterval, "Jaeger buffer flush interval")
	flags.IntVar(&jaegerOptions.QueueSize, "jaeger-queue-size", jaegerOptions.QueueSize, "Jaeger queue size")
	flags.StringVar(&jaegerOptions.Tags, "jaeger-tags", jaegerOptions.Tags, "Jaeger tags, comma separated list of name=value")
	flags.BoolVar(&jaegerOptions.Debug, "jaeger-debug", jaegerOptions.Debug, "Jaeger debug")

	flags.StringVar(&telegramOptions.BotToken, "telegram-bot-token", telegramOptions.BotToken, "Telegram bot token")
	flags.BoolVar(&telegramOptions.Debug, "telegram-debug", telegramOptions.Debug, "Telegram debug")
	flags.IntVar(&telegramOptions.Timeout, "telegram-timeout", telegramOptions.Timeout, "Telegram timeout")

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
