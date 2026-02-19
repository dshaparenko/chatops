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
	"github.com/devopsext/chatops/server"
	"github.com/slack-go/slack"

	// pprof is always enabled on the Prometheus listener because importing this
	// package registers its handlers on DefaultServeMux via init(). The Prometheus
	// sre provider calls http.Serve(listener, nil) which uses DefaultServeMux, so
	// /debug/pprof/* endpoints are available on the metrics port unconditionally.
	_ "net/http/pprof"

	sreCommon "github.com/devopsext/sre/common"
	sreProvider "github.com/devopsext/sre/provider"
	utils "github.com/devopsext/utils"
	"github.com/spf13/cobra"
)

var version = "unknown"
var APPNAME = "CHATOPS"

var logs = sreCommon.NewLogs()
var metrics = sreCommon.NewMetrics()
var stdout *sreProvider.Stdout
var mainWG sync.WaitGroup

type RootOptions struct {
	Logs    []string
	Metrics []string
}

var httpServerInstance *server.HttpServer

var httpServerOptions = server.HttpServerOptions{
	Listen:      envGet("HTTP_SERVER_LISTEN", ":8081").(string),
	AllowedCmds: strings.Split(envGet("HTTP_SERVER_ALLOWED_CMDS", "release").(string), ","),
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
	URL:       envGet("PROMETHEUS_METRICS_URL", "/metrics").(string),
	Listen:    envGet("PROMETHEUS_METRICS_LISTEN", "127.0.0.1:8080").(string),
	Prefix:    envGet("PROMETHEUS_METRICS_PREFIX", "chatops").(string),
	GoRuntime: envGet("PROMETHEUS_METRICS_GO_RUNTIME", true).(bool),
}

var telegramOptions = bot.TelegramOptions{
	BotToken: envGet("TELEGRAM_BOT_TOKEN", "").(string),
	Debug:    envGet("TELEGRAM_DEBUG", false).(bool),
	Timeout:  envGet("TELEGRAM_TIMEOUT", 60).(int),
	Offset:   envGet("TELEGRAM_OFFSET", 0).(int),
}

var slackOptions = bot.SlackOptions{
	BotToken:         envGet("SLACK_BOT_TOKEN", "").(string),
	AppToken:         envGet("SLACK_APP_TOKEN", "").(string),
	Debug:            envGet("SLACK_DEBUG", false).(bool),
	DefaultCommand:   envGet("SLACK_DEFAULT_COMMAND", "").(string),
	HelpCommand:      envGet("SLACK_HELP_COMMAND", "").(string),
	GroupPermissions: envGet("SLACK_GROUP_PERMISSIONS", "").(string),
	UserPermissions:  envGet("SLACK_USER_PERMISSIONS", "").(string),
	Timeout:          envGet("SLACK_TIMEOUT", 5).(int),
	PublicChannel:    envGet("SLACK_PUBLIC_CHANNEL", "").(string),

	ApprovalAny:         envGet("SLACK_APPROVAL_ANY", false).(bool),
	ApprovalReply:       envGet("SLACK_APPROVAL_REPLY", "").(string),
	ApprovalReasons:     envGet("SLACK_APPROVAL_REASONS", "*Reasons:*").(string),
	ApprovalDescription: envGet("SLACK_APPROVAL_DESCRIPTION", "").(string),

	AttachmentColor:   envGet("SLACK_ATTACHMENT_COLOR", "#555555").(string),
	ErrorColor:        envGet("SLACK_ERROR_COLOR", "#ff0000").(string),
	TitleConfirmation: envGet("SLACK_TITLE_CONFIRMATION", "Confirmation").(string),

	ApprovedMessage: envGet("SLACK_APPROVED_MESSAGE", "approved").(string),
	RejectedMessage: envGet("SLACK_REJECTED_MESSAGE", "rejected").(string),
	WaitingMessage:  envGet("SLACK_WAITING_MESSAGE", "waiting for approval").(string),

	ReactionDoing:    envGet("SLACK_REACTION_DOING", "spinner").(string),
	ReactionDone:     envGet("SLACK_REACTION_DONE", "white_check_mark").(string),
	ReactionFailed:   envGet("SLACK_REACTION_FAILED", "x").(string),
	ReactionForm:     envGet("SLACK_REACTION_FORM", "question").(string),
	ReactionApproval: envGet("SLACK_REACTION_APPROVAL", "eyes").(string),
	ReactionApproved: envGet("SLACK_REACTION_APPROVED", "white_check_mark").(string),
	ReactionRejected: envGet("SLACK_REACTION_REJECTED", "x").(string),

	ButtonSubmitCaption:  envGet("SLACK_BUTTON_SUBMIT_CAPTION", "OK").(string),
	ButtonSubmitStyle:    envGet("SLACK_BUTTON_SUBMIT_STYLE", string(slack.StylePrimary)).(string),
	ButtonCancelCaption:  envGet("SLACK_BUTTON_CANCEL_CAPTION", "Cancel").(string),
	ButtonCancelStyle:    envGet("SLACK_BUTTON_CANCEL_STYLE", "").(string),
	ButtonConfirmCaption: envGet("SLACK_BUTTON_CONFIRM_CAPTION", "Confirm").(string),
	ButtonRejectCaption:  envGet("SLACK_BUTTON_REJECT_CAPTION", "Reject").(string),
	ButtonApproveCaption: envGet("SLACK_BUTTON_APPROVE_CAPTION", "Approve").(string),

	CacheTTL:            envGet("SLACK_CACHE_TTL", "1h").(string),
	CacheTagMessagesTTL: envGet("SLACK_CACHE_TAG_MESSAGES_TTL", "720h").(string), // 30 days (approximately 1 month)
	MaxQueryOptions:     envGet("SLACK_MAX_QUERY_OPTIONS", 15).(int),
	MinQueryLength:      envGet("SLACK_MIN_QUERY_LENGTH", 2).(int),

	UserGroupsInterval: envGet("SLACK_USER_GROUPS_INTERVAL", 5).(int),

	CacheFileName: envGet("SLACK_CACHE_FILE_NAME", "").(string),
}

var defaultOptions = processor.DefaultOptions{
	CommandsDir:  envGet("DEFAULT_COMMANDS_DIR", "").(string),
	TemplatesDir: envGet("DEFAULT_TEMPLATES_DIR", "").(string),
	RunbooksDir:  envGet("DEFAULT_RUNBOOKS_DIR", "").(string),
	CommandExt:   envGet("DEFAULT_COMMAND_EXT", ".tpl").(string),
	ConfigExt:    envGet("DEFAULT_CONFIG_EXT", ".yml").(string),
	Error:        envGet("DEFAULT_ERROR", "Couldn't execute command").(string),
}

func envGet(s string, def interface{}) interface{} {
	return utils.EnvGet(fmt.Sprintf("%s_%s", APPNAME, s), def)
}

// botsInstance holds a reference to the bots for shutdown
var botsInstance *common.Bots

func interceptSyscall() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-c
		logs.Info("Graceful shutdown initiated...")

		// Call Stop on all bots if available
		if botsInstance != nil {
			logs.Info("Stopping bots...")
			botsInstance.Stop()
		}

		// Call Stop on HTTP server if available
		if httpServerInstance != nil {
			logs.Info("Stopping HTTP server...")
			httpServerInstance.Stop()
		}

		logs.Info("Exiting...")
		os.Exit(0)
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
			//sre provider calls http.Serve(listener, nil) which uses DefaultServeMux !
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

			// Store bots reference for graceful shutdown
			botsInstance = bots

			// Create and start HTTP server (bots implements CommandExecutor)
			httpServer := server.NewHttpServer(httpServerOptions, obs, bots)
			httpServerInstance = httpServer
			httpServer.Start(&mainWG)

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
	flags.StringVar(&slackOptions.ReactionDoing, "slack-reaction-doing", slackOptions.ReactionDoing, "Slack reaction doing name")
	flags.StringVar(&slackOptions.ReactionDone, "slack-reaction-done", slackOptions.ReactionDone, "Slack reaction done name")
	flags.StringVar(&slackOptions.ReactionFailed, "slack-reaction-failed", slackOptions.ReactionFailed, "Slack reaction failed name")
	flags.StringVar(&slackOptions.DefaultCommand, "slack-default-command", slackOptions.DefaultCommand, "Slack default command")
	flags.StringVar(&slackOptions.HelpCommand, "slack-help-command", slackOptions.HelpCommand, "Slack help command")
	flags.StringVar(&slackOptions.GroupPermissions, "slack-group-permissions", slackOptions.GroupPermissions, "Slack group permissions")
	flags.StringVar(&slackOptions.UserPermissions, "slack-user-permissions", slackOptions.UserPermissions, "Slack user permissions")
	flags.IntVar(&slackOptions.Timeout, "slack-timeout", slackOptions.Timeout, "Slack timeout")
	flags.StringVar(&slackOptions.PublicChannel, "slack-public-channel", slackOptions.PublicChannel, "Slack public channel")
	flags.StringVar(&slackOptions.AttachmentColor, "slack-attachment-color", slackOptions.AttachmentColor, "Slack attachment color")
	flags.StringVar(&slackOptions.ErrorColor, "slack-error-color", slackOptions.ErrorColor, "Slack error color")
	flags.StringVar(&slackOptions.WaitingMessage, "slack-waiting-message", slackOptions.WaitingMessage, "Slack waiting approval message")
	flags.StringVar(&slackOptions.ApprovedMessage, "slack-approved-message", slackOptions.ApprovedMessage, "Slack approved message")
	flags.StringVar(&slackOptions.RejectedMessage, "slack-rejected-message", slackOptions.RejectedMessage, "Slack rejected message")
	flags.StringVar(&slackOptions.CacheFileName, "slack-cache-file-name", slackOptions.CacheFileName, "Slack cache file name")
	flags.StringVar(&slackOptions.CacheTTL, "slack-cache-ttl", slackOptions.CacheTTL, "Slack cache TTL")
	flags.StringVar(&slackOptions.CacheTagMessagesTTL, "slack-cache-tag-messages-ttl", slackOptions.CacheTagMessagesTTL, "Slack cache tag messages TTL")
	flags.IntVar(&slackOptions.MaxQueryOptions, "slack-max-query-options", slackOptions.MaxQueryOptions, "Slack max query options")
	flags.IntVar(&slackOptions.MinQueryLength, "slack-min-query-length", slackOptions.MinQueryLength, "Slack min query length")
	flags.IntVar(&slackOptions.UserGroupsInterval, "slack-user-groups-interval", slackOptions.UserGroupsInterval, "Slack user groups interval")

	flags.StringVar(&defaultOptions.CommandsDir, "default-commands-dir", defaultOptions.CommandsDir, "Default commands directory")
	flags.StringVar(&defaultOptions.TemplatesDir, "default-templates-dir", defaultOptions.TemplatesDir, "Default templates directory")
	flags.StringVar(&defaultOptions.CommandExt, "default-command-ext", defaultOptions.CommandExt, "Default command extension")
	flags.StringVar(&defaultOptions.ConfigExt, "default-config-ext", defaultOptions.ConfigExt, "Default config extension")
	flags.StringVar(&defaultOptions.Error, "default-error", defaultOptions.Error, "Default error")

	flags.StringVar(&httpServerOptions.Listen, "http-server-listen", httpServerOptions.Listen, "HTTP server listen address (e.g., :8081)")
	flags.StringSliceVar(&httpServerOptions.AllowedCmds, "http-server-allowed-cmds", httpServerOptions.AllowedCmds, "HTTP server allowed commands (comma-separated)")

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
