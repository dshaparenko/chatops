module github.com/devopsext/chatops

go 1.24.1

replace gopkg.in/DataDog/dd-trace-go.v1 => github.com/devopsext/dd-trace-go v1.31.2

replace github.com/slack-io/slacker => github.com/devopsext/slacker v0.1.1-3

//replace github.com/devopsext/tools => ./../tools

//replace github.com/devopsext/slacker => ./../slacker

require (
	github.com/devopsext/sre v0.6.3
	github.com/devopsext/tools v0.17.1
	github.com/devopsext/utils v0.4.7
	github.com/go-telegram-bot-api/telegram-bot-api v4.6.4+incompatible
	github.com/google/uuid v1.6.0
	github.com/jellydator/ttlcache/v3 v3.3.0
	github.com/jinzhu/copier v0.4.0
	github.com/slack-go/slack v0.13.0
	github.com/slack-io/slacker v0.1.1-3
	github.com/spf13/cobra v1.8.0
	golang.org/x/sync v0.10.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/DataDog/datadog-api-client-go v1.7.0 // indirect
	github.com/DataDog/datadog-go v4.7.0+incompatible // indirect
	github.com/DataDog/sketches-go v1.0.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.2 // indirect
	github.com/Microsoft/go-winio v0.5.0 // indirect
	github.com/VictoriaMetrics/metrics v1.33.1 // indirect
	github.com/araddon/dateparse v0.0.0-20210429162001-6b43995a97de // indirect
	github.com/blues/jsonata-go v1.5.4 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.7 // indirect
	github.com/go-ldap/ldap/v3 v3.4.10 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/huandu/xstrings v1.3.1 // indirect
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/mitchellh/copystructure v1.0.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.0 // indirect
	github.com/newrelic/newrelic-telemetry-sdk-go v0.8.1 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/philhofer/fwd v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/rs/xid v1.3.0 // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/slack-io/commander v0.0.0-20231120025847-9fd78b4b2d54 // indirect
	github.com/slack-io/proper v0.0.0-20231119200853-f78ba4fc878f // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	github.com/technoweenie/multipartstreamer v1.0.1 // indirect
	github.com/tidwall/gjson v1.17.1 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tinylib/msgp v1.1.2 // indirect
	github.com/uber/jaeger-client-go v2.29.1+incompatible // indirect
	github.com/uber/jaeger-lib v2.4.1+incompatible // indirect
	github.com/valyala/fastrand v1.1.0 // indirect
	github.com/valyala/histogram v1.2.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/oauth2 v0.24.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/time v0.0.0-20210608053304-ed9ce3a009e4 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/DataDog/dd-trace-go.v1 v1.31.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
