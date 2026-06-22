// Kafka adapter for the graph_ws broadcaster (T1.4 — v8.0).
//
// A KafkaSource wraps segmentio/kafka-go's Reader so the broadcaster
// doesn't have to know about Kafka semantics. The Reader is configured
// for "live tail": it joins a uniquely-named consumer group so each
// pod sees every envelope, and starts from latest so we never replay
// stale graph history when a websocket pod recycles.
package graph_ws

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/beenuar/aisoc/services/ingest/internal/graph"
	kafka "github.com/segmentio/kafka-go"
)

// KafkaSourceConfig describes how to attach to the graph-updates topic.
type KafkaSourceConfig struct {
	// Brokers is a comma-separated bootstrap server list.
	Brokers string
	// Topic is the graph-updates topic. Production: "security.graph_updates".
	Topic string
	// GroupID is the consumer group. Empty => derived from hostname so
	// every pod consumes every message (live-tail semantics).
	GroupID string
	// StartOffset chooses where a new group reads from. Accepts
	// kafka.FirstOffset or kafka.LastOffset; defaults to LastOffset
	// because the WS contract is "live tail, no replay".
	StartOffset int64
}

// KafkaSource is the production EnvelopeSource. It owns a kafka.Reader
// and decodes each message into a graph.GraphUpdate.
type KafkaSource struct {
	reader *kafka.Reader
}

// NewKafkaSource builds a KafkaSource. The caller is responsible for
// calling Close to release the underlying connection.
func NewKafkaSource(cfg KafkaSourceConfig) (*KafkaSource, error) {
	if cfg.Brokers == "" {
		return nil, fmt.Errorf("graph_ws: kafka brokers required")
	}
	if cfg.Topic == "" {
		return nil, fmt.Errorf("graph_ws: kafka topic required")
	}
	group := cfg.GroupID
	if group == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "graph-ws"
		}
		group = "graph-ws-" + host
	}
	start := cfg.StartOffset
	if start == 0 {
		start = kafka.LastOffset
	}
	rd := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     splitCSV(cfg.Brokers),
		Topic:       cfg.Topic,
		GroupID:     group,
		StartOffset: start,
		MinBytes:    1,
		MaxBytes:    10 * 1024 * 1024,
	})
	return &KafkaSource{reader: rd}, nil
}

// Next implements EnvelopeSource.
func (k *KafkaSource) Next(ctx context.Context) (graph.GraphUpdate, error) {
	msg, err := k.reader.ReadMessage(ctx)
	if err != nil {
		return graph.GraphUpdate{}, err
	}
	var env graph.GraphUpdate
	if err := json.Unmarshal(msg.Value, &env); err != nil {
		return graph.GraphUpdate{}, fmt.Errorf("graph_ws: decode envelope: %w", err)
	}
	if env.TenantID == "" {
		for _, h := range msg.Headers {
			if h.Key == "tenant_id" {
				env.TenantID = string(h.Value)
				break
			}
		}
	}
	return env, nil
}

// Close implements EnvelopeSource.
func (k *KafkaSource) Close() error {
	if k.reader == nil {
		return nil
	}
	return k.reader.Close()
}

func splitCSV(s string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		if r == ' ' {
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
