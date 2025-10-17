package common

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/pubsub"
	sreCommon "github.com/devopsext/sre/common"
	"google.golang.org/api/option"
)

type PubSub struct {
	options       PubSubOptions
	logger        sreCommon.Logger
	observability *Observability
	client        *pubsub.Client
}

type PubSubOptions struct {
	Credentials        string
	ProjectID          string
	TopicID            string
	SubscriptionID     string
	AckDeadlineSeconds int
	RetentionSeconds   int
	CacheDir           string
}

type PubSubMessagePayloadFile struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
}

type PubSubMessagePayloadFiles = []*PubSubMessagePayloadFile

type PubSubMessagePayloadKind = int

const (
	PubSubMessagePayloadKindUnknown int = iota
	PubSubMessagePayloadKindFile
	PubSubMessagePayloadKindFiles
)

type PubSubMessagePayloadCompression = int

const (
	PubSubMessagePayloadCompressionNone int = iota
	PubSubMessagePayloadCompressionGZip
)

type PubSubMessagePayload struct {
	Kind        PubSubMessagePayloadKind        `json:"kind"`
	Compression PubSubMessagePayloadCompression `json:"compression"`
	Data        []byte                          `json:"data"`
}

type PubSubMessage struct {
	Payload map[string]*PubSubMessagePayload `json:"payload"`
}

// decompress decompresses payload data based on compression type
func (ps *PubSub) decompress(payload *PubSubMessagePayload) ([]byte, error) {
	switch payload.Compression {
	case PubSubMessagePayloadCompressionGZip:
		buf := bytes.NewReader(payload.Data)
		zr, err := gzip.NewReader(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer zr.Close()

		data, err := io.ReadAll(zr)
		if err != nil {
			return nil, fmt.Errorf("failed to read gzip data: %w", err)
		}
		return data, nil
	case PubSubMessagePayloadCompressionNone:
		return payload.Data, nil
	default:
		return nil, fmt.Errorf("unknown compression type: %d", payload.Compression)
	}
}

func (ps *PubSub) StartAsync() {
	ps.logger.Info("PubSub starting async listener...")
	go ps.Start()
}

func (ps *PubSub) Start() {
	ps.startWithContext(context.Background())
}

func (ps *PubSub) startWithContext(ctx context.Context) {
	ps.logger.Debug("PubSub discovery starting for topic: %s", ps.options.TopicID)
	ps.logger.Debug("PubSub subscription: %s", ps.options.SubscriptionID)
	ps.logger.Debug("PubSub project: %s", ps.options.ProjectID)

	topic := ps.client.Topic(ps.options.TopicID)
	subID := ps.options.SubscriptionID

	// check if topic exists first
	topicExists, err := topic.Exists(ctx)
	if err != nil {
		ps.logger.Error("PubSub topic %s existence check error: %s", ps.options.TopicID, err)
		return
	}
	if !topicExists {
		ps.logger.Error("PubSub topic %s does not exist!", ps.options.TopicID)
		return
	}

	sub := ps.client.Subscription(subID)
	exists, err := sub.Exists(ctx)
	if err != nil {
		ps.logger.Error("PubSub subscription %s existence check error: %s", subID, err)
		return
	}

	if !exists {
		ps.logger.Info("PubSub subscription %s does not exist, creating...", subID)
		sub, err = ps.client.CreateSubscription(ctx, subID, pubsub.SubscriptionConfig{
			Topic:             topic,
			AckDeadline:       time.Duration(ps.options.AckDeadlineSeconds) * time.Second,
			RetentionDuration: time.Duration(ps.options.RetentionSeconds) * time.Second,
		})
		if err != nil {
			ps.logger.Error("PubSub subscription %s creation error: %s", subID, err)
			return
		}
	} else {
		ps.logger.Debug("PubSub subscription %s already exists", subID)
	}

	// // try to get subscription info to see current state
	// config, err := sub.Config(ctx)
	// if err != nil {
	// 	ps.logger.Warn("Could not get subscription config: %v", err)
	// } else {
	// 	ps.logger.Debug("PubSub subscription config - AckDeadline: %v, RetentionDuration: %v",
	// 		config.AckDeadline, config.RetentionDuration)
	// }

	err = sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {

		var pm PubSubMessage
		err := json.Unmarshal(msg.Data, &pm)
		if err != nil {
			msg.Nack()
			ps.logger.Error("PubSub couldn't unmarshal message %s from %s error: %s", msg.ID, subID, err)
			return
		}

		m := make(map[string]any)
		processedCount := 0

		for k, v := range pm.Payload {

			if v.Kind == PubSubMessagePayloadKindUnknown {
				ps.logger.Error("PubSub couldn't process unknown payload %s from %s", k, subID)
				continue
			}

			data, err := ps.decompress(v)
			if err != nil {
				ps.logger.Error("PubSub couldn't decompress payload %s from %s error: %s", k, subID, err)
				continue
			}

			switch v.Kind {
			case PubSubMessagePayloadKindFile:
				var f PubSubMessagePayloadFile
				err := json.Unmarshal(data, &f)
				if err != nil {
					ps.logger.Error("PubSub couldn't unmarshall payload %s from %s to file error: %s", k, subID, err)
					continue
				}
				name := filepath.Base(f.Path)
				ps.logger.Debug("PubSub processing single file: %s", name)

				// store the file with proper JSON formatting
				ps.storeFile(name, f.Data)
				m[name] = &f
				processedCount++

			case PubSubMessagePayloadKindFiles:
				var fs []*PubSubMessagePayloadFile
				err := json.Unmarshal(data, &fs)
				if err != nil {
					ps.logger.Error("PubSub couldn't unmarshall payload %s from %s to files error: %s", k, subID, err)
					continue
				}

				for _, f := range fs {
					name := filepath.Base(f.Path)
					ps.logger.Debug("PubSub processing file: %s", name)
					ps.storeFile(name, f.Data)
					m[name] = f
					processedCount++
				}
			case PubSubMessagePayloadKindUnknown:
				ps.logger.Error("PubSub couldn't process unknown payload %s from %s", k, subID)
			}
		}
		msg.Ack()

		ps.logger.Info("PubSub processed message %s: %d payloads, %d files stored", msg.ID, len(pm.Payload), processedCount)
	})

	if err != nil {
		ps.logger.Error("PubSub couldn't receive messages from %s error: %s", subID, err)
		return
	}

}

func (ps *PubSub) storeFile(filename string, data []byte) {
	cacheDir := ps.options.CacheDir
	if cacheDir == "" {
		cacheDir = "cache/asset"
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		ps.logger.Error("Failed to create cache directory: %v", err)
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	if filename == "." || filename == "/" || filename == "" {
		filename = fmt.Sprintf("%s_assets.json", timestamp)
	}

	filePath := filepath.Join(cacheDir, filename)

	// try to parse and store as formatted JSON
	var jsonData any
	if err := json.Unmarshal(data, &jsonData); err != nil {
		ps.logger.Debug("File data is not valid JSON for %s: %v", filename, err)
	} else {
		// Store as formatted JSON
		formattedJSON, err := json.MarshalIndent(jsonData, "", "  ")
		if err != nil {
			ps.logger.Error("Failed to marshal JSON for %s: %v", filename, err)
			return
		}
		if err := os.WriteFile(filePath, formattedJSON, 0644); err != nil {
			ps.logger.Error("Failed to write JSON file %s: %v", filename, err)
			return
		}
	}

}

func NewPubSub(options PubSubOptions, observability *Observability, logger sreCommon.Logger) *PubSub {
	logger.Debug("NewPubSub called with project: %s, topic: %s, subscription: %s",
		options.ProjectID, options.TopicID, options.SubscriptionID)

	if options.Credentials == "" || options.TopicID == "" ||
		options.SubscriptionID == "" || options.ProjectID == "" {
		logger.Debug("PubSub is disabled. Missing required options. Skipped")
		return nil
	}

	logger.Debug("PubSub checking credentials file: %s", options.Credentials)

	var credsOpt option.ClientOption
	_, err := os.Stat(options.Credentials)
	if err != nil {
		logger.Debug("PubSub using credentials as raw JSON content")
		// try as raw JSON content
		credsOpt = option.WithCredentialsJSON([]byte(options.Credentials))
	} else {
		logger.Debug("PubSub using credentials file path")
		// use file path
		credsOpt = option.WithCredentialsFile(options.Credentials)
	}

	logger.Debug("PubSub creating client for project: %s", options.ProjectID)
	client, err := pubsub.NewClient(context.Background(), options.ProjectID, credsOpt)
	if err != nil {
		logger.Error("PubSub new client error: %s", err)
		return nil
	}

	logger.Info("PubSub client created successfully for project: %s", options.ProjectID)

	return &PubSub{
		options:       options,
		logger:        logger,
		observability: observability,
		client:        client,
	}
}
