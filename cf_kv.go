package caddy_storage_cf_kv

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/cloudflare/cloudflare-go"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CloudflareKVStorage{})
}

// CloudflareKVStorage implements a Caddy storage backend for Cloudflare KV
type CloudflareKVStorage struct {
	Logger            *zap.SugaredLogger `json:"-"`
	ctx               context.Context
	client            *cloudflare.API
	resourceContainer *cloudflare.ResourceContainer
	APIToken          string `json:"api_token,omitempty"`    // The Cloudflare API token
	AccountID         string `json:"account_id,omitempty"`   // Cloudflare Account ID
	NamespaceID       string `json:"namespace_id,omitempty"` // KV Namespace ID
}

type StorageData struct {
	Value    []byte    `json:"value"`
	Modified time.Time `json:"modified"`
}

// Interface guards
var (
	_ caddy.Module           = (*CloudflareKVStorage)(nil)
	_ caddy.StorageConverter = (*CloudflareKVStorage)(nil)
	_ caddyfile.Unmarshaler  = (*CloudflareKVStorage)(nil)
	_ caddy.Provisioner      = (*CloudflareKVStorage)(nil)
	_ certmagic.Storage      = (*CloudflareKVStorage)(nil)
)

func (CloudflareKVStorage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.cloudflare_kv",
		New: func() caddy.Module {
			return new(CloudflareKVStorage)
		},
	}
}

func (s *CloudflareKVStorage) CertMagicStorage() (certmagic.Storage, error) {
	return s, nil
}

func (s *CloudflareKVStorage) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		key := d.Val()
		var value string
		if !d.Args(&value) {
			continue
		}

		switch key {
		case "api_token":
			s.APIToken = value
		case "account_id":
			s.AccountID = value
		case "namespace_id":
			s.NamespaceID = value
		}
	}
	return nil
}

func (s *CloudflareKVStorage) Provision(ctx caddy.Context) error {
	s.Logger = ctx.Logger(s).Sugar()
	s.ctx = ctx.Context

	s.APIToken = strEnvOrDefault(s.APIToken, "CADDY_CLOUDFLARE_API_TOKEN", "")
	s.AccountID = strEnvOrDefault(s.AccountID, "CADDY_CLOUDFLARE_ACCOUNT_ID", "")
	s.NamespaceID = strEnvOrDefault(s.NamespaceID, "CADDY_CLOUDFLARE_NAMESPACE_ID", "")

	if s.APIToken == "" {
		return fmt.Errorf("api_token must be provided")
	}

	var err error
	s.client, err = cloudflare.NewWithAPIToken(s.APIToken)
	if err != nil {
		return fmt.Errorf("error creating Cloudflare client: %v", err)
	}

	if s.AccountID == "" || s.NamespaceID == "" {
		return fmt.Errorf("both account_id and namespace_id must be provided")
	}

	_, err = s.client.ListWorkersKVKeys(s.ctx, s.resourceContainer, cloudflare.ListWorkersKVsParams{
		NamespaceID: s.NamespaceID,
		Limit:       1,
	})
	if err != nil {
		return fmt.Errorf("failed to verify Cloudflare KV namespace: %v", err)
	}

	s.Logger.Infof("Cloudflare KV Storage initialized for namespace %s'", s.NamespaceID)

	s.resourceContainer = &cloudflare.ResourceContainer{
		Level:      cloudflare.AccountRouteLevel,
		Identifier: s.AccountID,
	}

	return nil
}

func (s *CloudflareKVStorage) Store(_ context.Context, key string, value []byte) error {
	data := &StorageData{
		Value:    value,
		Modified: time.Now(),
	}
	serialized, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("unable to encode data for key %s: %v", key, err)
	}

	params := cloudflare.WriteWorkersKVEntryParams{
		Key:   key,
		Value: serialized,
	}
	_, err = s.client.WriteWorkersKVEntry(s.ctx, s.resourceContainer, params)
	if err != nil {
		return fmt.Errorf("failed to write KV entry: %v", err)
	}

	return nil
}

func (s *CloudflareKVStorage) Load(_ context.Context, key string) ([]byte, error) {
	dataBytes, err := s.getData(key)
	if err != nil {
		return nil, err
	}

	var data StorageData
	err = json.Unmarshal(dataBytes, &data)
	if err != nil {
		return nil, fmt.Errorf("unable to decode data for key %s: %v", key, err)
	}
	return data.Value, nil
}

func (s *CloudflareKVStorage) Delete(_ context.Context, key string) error {
	_, err := s.getData(key)
	if err != nil {
		return err
	}

	params := cloudflare.DeleteWorkersKVEntryParams{
		Key: key,
	}
	_, err = s.client.DeleteWorkersKVEntry(s.ctx, s.resourceContainer, params)
	if err != nil {
		return fmt.Errorf("failed to delete KV entry: %v", err)
	}

	return nil
}

func (s *CloudflareKVStorage) Exists(_ context.Context, key string) bool {
	_, err := s.getData(key)
	return err == nil
}

func (s *CloudflareKVStorage) List(_ context.Context, path string, recursive bool) ([]string, error) {
	var allKeys []string

	cursor := ""
	for {
		resp, err := s.client.ListWorkersKVKeys(s.ctx, s.resourceContainer, cloudflare.ListWorkersKVsParams{
			NamespaceID: s.NamespaceID,
			Cursor:      cursor,
		})

		if err != nil {
			return nil, fmt.Errorf("error listing keys with prefix '%s': %v", path, err)
		}

		for _, k := range resp.Result {
			allKeys = append(allKeys, k.Name)
		}

		if resp.Cursor == "" {
			break
		}
		cursor = resp.Cursor
	}

	// If recursive or wildcard prefix, return all. Otherwise, emulate "directories".
	if recursive || path == "" || path == "*" {
		return allKeys, nil
	}

	var keysFound []string
	for _, k := range allKeys {
		if strings.HasPrefix(k, path+"/") {
			keysFound = append(keysFound, k)
		}
	}
	return keysFound, nil
}

func (s *CloudflareKVStorage) Stat(_ context.Context, key string) (certmagic.KeyInfo, error) {
	dataBytes, err := s.getData(key)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	var data StorageData
	if err := json.Unmarshal(dataBytes, &data); err != nil {
		return certmagic.KeyInfo{}, fmt.Errorf("unable to decode data for key %s: %v", key, err)
	}
	return certmagic.KeyInfo{
		Key:        key,
		Modified:   data.Modified,
		Size:       int64(len(data.Value)),
		IsTerminal: false,
	}, nil
}

func (s *CloudflareKVStorage) Lock(ctx context.Context, key string) error {
	return nil
}

func (s *CloudflareKVStorage) Unlock(_ context.Context, key string) error {
	return nil
}

// getData is a helper that fetches the raw value from Cloudflare KV.
func (s *CloudflareKVStorage) getData(fullKey string) ([]byte, error) {
	val, err := s.client.GetWorkersKV(s.ctx, s.resourceContainer, cloudflare.GetWorkersKVParams{
		NamespaceID: s.NamespaceID,
		Key:         fullKey,
	})
	if err != nil {
		// If it's a 404 from CF, translate to fs.ErrNotExist
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not found") {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	if len(val) == 0 {
		// Cloudflare returns an empty string if key not found
		return nil, fs.ErrNotExist
	}
	return []byte(val), nil
}

// get string from env var if not already set
func strEnvOrDefault(current, envVar, def string) string {
	if current != "" {
		return current
	}
	if val := os.Getenv(envVar); val != "" {
		return val
	}
	return def
}

func (s CloudflareKVStorage) String() string {
	type Redacted CloudflareKVStorage

	r := Redacted(s)
	r.APIToken = "REDACTED"

	out, _ := json.Marshal(r)
	return string(out)
}
