package common

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cloud.google.com/go/pubsub"
	sreCommon "github.com/devopsext/sre/common"
	"google.golang.org/api/option"
)

type PubSub struct {
	options       PubSubOptions
	observability *Observability
	logger        sreCommon.Logger

	client       *pubsub.Client
	subscription *pubsub.Subscription
	ctx          context.Context
	cancelFunc   context.CancelFunc
}

type PubSubOptions struct {
	ProjectID string

	TopicID string

	SubscriptionID string

	// can be the raw JSON content of a service account key or a
	// file path to the service account JSON key.
	Credentials string

	AckDeadlineSeconds int

	RetentionSeconds int

	// MaxOutstandingMessages is the maximum number of unacknowledged messages the
	MaxOutstandingMessages int

	// the number of goroutines used to pull and process messages.
	NumGoroutines int

	// CacheDir is the directory where JSON payloads will be stored
	CacheDir string
}

type PubSubMessage struct {
	Payload map[string]*PubSubMessagePayload `json:"payload"`
}

type PubSubMessagePayload struct {
	Kind        PayloadKind        `json:"kind"`
	Compression PayloadCompression `json:"compression"`
	Metadata    map[string]string  `json:"metadata"`
	Data        []byte             `json:"data"`
}

type PayloadKind string

const (
	KindFile      PayloadKind = "FILE"
	KindEventData PayloadKind = "EVENT_DATA"
)

type PayloadCompression string

const (
	CompressionNone PayloadCompression = "NONE"
	CompressionGzip PayloadCompression = "GZIP"
)

func (ps *PubSub) storeJSON(id string, payload *PubSubMessagePayload) error {
	cacheDir := ps.options.CacheDir
	if cacheDir == "" {
		cacheDir = "cache/asset"
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s_%s.json", timestamp, string(payload.Kind), id)
	filePath := filepath.Join(cacheDir, filename)

	dataToStore := map[string]interface{}{
		"id":          id,
		"kind":        payload.Kind,
		"compression": payload.Compression,
		"metadata":    payload.Metadata,
		"data":        payload.Data,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}

	jsonData, err := json.MarshalIndent(dataToStore, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal payload to JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	ps.logger.Info("Stored payload ID %s as JSON file: %s", id, filePath)
	return nil
}

func (ps *PubSub) Start() error {
	ps.ctx, ps.cancelFunc = context.WithCancel(context.Background())

	client, err := ps.newPubSubClient(ps.ctx)
	if err != nil {
		return fmt.Errorf("failed to create pubsub client: %w", err)
	}
	ps.client = client

	sub, err := ps.ensureSubscription(ps.ctx)
	if err != nil {
		return fmt.Errorf("failed to ensure subscription exists: %w", err)
	}
	ps.subscription = sub

	go ps.receive(ps.ctx)

	ps.logger.Info("PubSub service started. Listening for messages on subscription %s", ps.options.SubscriptionID)
	return nil
}

func (ps *PubSub) Stop() error {
	ps.logger.Info("Stopping PubSub service...")

	if ps.cancelFunc != nil {
		ps.cancelFunc()
	}

	if ps.client != nil {
		if err := ps.client.Close(); err != nil {
			return fmt.Errorf("failed to close pubsub client: %w", err)
		}
	}

	ps.logger.Info("PubSub service stopped.")
	return nil
}

// newPubSubClient creates the Google Cloud Pub/Sub client.
func (ps *PubSub) newPubSubClient(ctx context.Context) (*pubsub.Client, error) {
	// Handle credentials
	var credsOpt option.ClientOption
	if ps.options.Credentials != "" {
		// Check if it's a file path
		if _, err := os.Stat(ps.options.Credentials); err == nil {
			credsOpt = option.WithCredentialsFile(ps.options.Credentials)
		} else {
			// Assume it's raw JSON content
			credsOpt = option.WithCredentialsJSON([]byte(ps.options.Credentials))
		}
	}

	return pubsub.NewClient(ctx, ps.options.ProjectID, credsOpt)
}

// ensureSubscription checks if the subscription exists and creates it if it doesn't.
func (ps *PubSub) ensureSubscription(ctx context.Context) (*pubsub.Subscription, error) {
	sub := ps.client.Subscription(ps.options.SubscriptionID)
	exists, err := sub.Exists(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check for subscription existence: %w", err)
	}

	if exists {
		ps.logger.Info("Subscription %s already exists.", ps.options.SubscriptionID)
		return sub, nil
	}

	// subscription doesn't exist, so create it.
	ps.logger.Info("Subscription %s does not exist. Creating...", ps.options.SubscriptionID)

	topic := ps.client.Topic(ps.options.TopicID)
	exists, err = topic.Exists(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check for topic existence: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("topic %s does not exist, cannot create subscription", ps.options.TopicID)
	}

	subConfig := pubsub.SubscriptionConfig{
		Topic: topic,
	}
	if ps.options.AckDeadlineSeconds > 0 {
		subConfig.AckDeadline = time.Duration(ps.options.AckDeadlineSeconds) * time.Second
	}
	if ps.options.RetentionSeconds > 0 {
		subConfig.RetentionDuration = time.Duration(ps.options.RetentionSeconds) * time.Second
	}

	newSub, err := ps.client.CreateSubscription(ctx, ps.options.SubscriptionID, subConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create subscription: %w", err)
	}

	ps.logger.Info("Successfully created subscription %s for topic %s", ps.options.SubscriptionID, ps.options.TopicID)
	return newSub, nil
}

// handleMessage processes individual message payloads based on their kind
func (ps *PubSub) handleMessage(ctx context.Context, id string, payload *PubSubMessagePayload) error {
	switch payload.Kind {
	case KindFile:
		return ps.handleFilePayload(ctx, id, payload)
	case KindEventData:
		return ps.handleEventDataPayload(ctx, id, payload)
	default:
		ps.logger.Warn("Unknown payload kind: %s for payload ID %s", payload.Kind, id)
		return nil // don't fail for unknown kinds, just log
	}
}

// handleFilePayload processes file-type payloads
func (ps *PubSub) handleFilePayload(ctx context.Context, id string, payload *PubSubMessagePayload) error {
	ps.logger.Debug("Processing file payload ID %s with compression %s", id, payload.Compression)

	// Store the JSON data to cache/asset folder
	if err := ps.storeJSON(id, payload); err != nil {
		ps.logger.Error("Failed to store file payload %s: %v", id, err)
		return err
	}

	for key, value := range payload.Metadata {
		ps.logger.Debug("File payload %s metadata: %s = %s", id, key, value)
	}

	ps.logger.Info("Successfully processed and stored file payload ID %s", id)
	return nil
}

// handleEventDataPayload processes event-type payloads
func (ps *PubSub) handleEventDataPayload(ctx context.Context, id string, payload *PubSubMessagePayload) error {
	ps.logger.Debug("Processing event data payload ID %s with compression %s", id, payload.Compression)

	// Store the JSON data to cache/asset folder
	if err := ps.storeJSON(id, payload); err != nil {
		ps.logger.Error("Failed to store event data payload %s: %v", id, err)
		return err
	}

	// extract metadata for processing
	for key, value := range payload.Metadata {
		ps.logger.Debug("Event data payload %s metadata: %s = %s", id, key, value)
	}

	ps.logger.Info("Successfully processed and stored event data payload ID %s", id)
	return nil
}

// receive is the main message processing loop.
func (ps *PubSub) receive(ctx context.Context) {
	if ps.options.MaxOutstandingMessages > 0 {
		ps.subscription.ReceiveSettings.MaxOutstandingMessages = ps.options.MaxOutstandingMessages
	}
	if ps.options.NumGoroutines > 0 {
		ps.subscription.ReceiveSettings.NumGoroutines = ps.options.NumGoroutines
	}

	// start receiving messages. Receive blocks until the context is canceled or a fatal error occurs.
	err := ps.subscription.Receive(ctx, func(ctx context.Context, msg *pubsub.Message) {
		ps.logger.Debug("Received message: %s", msg.ID)

		var pubsubMsg PubSubMessage
		if err := json.Unmarshal(msg.Data, &pubsubMsg); err != nil {
			ps.logger.Error("Could not unmarshal message data for msg ID %s: %v. Nacking message.", msg.ID, err)
			msg.Nack()
			return
		}

		// process each payload in the message
		hasError := false
		for id, payload := range pubsubMsg.Payload {
			err := ps.handleMessage(ctx, id, payload)
			if err != nil {
				ps.logger.Error("Handler failed for payload ID %s (from message %s): %v. Nacking entire message.", id, msg.ID, err)
				hasError = true
				break
			}
		}

		if hasError {
			msg.Nack()
		} else {
			ps.logger.Debug("Successfully processed all payloads for message %s. Acking.", msg.ID)
			msg.Ack()
		}
	})

	if err != nil {
		ps.logger.Error("PubSub receiver unexpectedly stopped: %v", err)
	}
}

func NewPubSub(options PubSubOptions, observability *Observability, logger sreCommon.Logger) *PubSub {

	return &PubSub{
		options:       options,
		observability: observability,
		logger:        logger,
	}
}
