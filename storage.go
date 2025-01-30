package caddy_storage_cf_kv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/cloudflare/cloudflare-go/v3"
	"github.com/cloudflare/cloudflare-go/v3/kv"
	"github.com/cloudflare/cloudflare-go/v3/option"
	"go.uber.org/zap"
)

// Interface guards
var (
	_ caddy.Module           = (*CloudflareKVStorage)(nil)
	_ caddy.StorageConverter = (*CloudflareKVStorage)(nil)
	_ caddyfile.Unmarshaler  = (*CloudflareKVStorage)(nil)
	_ caddy.Provisioner      = (*CloudflareKVStorage)(nil)
	_ certmagic.Storage      = (*CloudflareKVStorage)(nil)
)

func init() {
	caddy.RegisterModule(CloudflareKVStorage{})
}

// CloudflareKVStorage implements a Caddy storage backend for Cloudflare KV
type CloudflareKVStorage struct {
	Logger      *zap.SugaredLogger `json:"-"`
	ctx         context.Context
	client      *cloudflare.Client
	APIToken    string `json:"api_token,omitempty"`    // The Cloudflare API token
	AccountID   string `json:"account_id,omitempty"`   // Cloudflare Account ID
	NamespaceID string `json:"namespace_id,omitempty"` // KV Namespace ID
}

type Metadata struct {
	Modified time.Time `json:"modified"`
}

type LoadValueResponse struct {
	MetadataJsonString string `json:"metadata"`
	Value              string `json:"value"`
}

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

	// This adds support to the documented Caddy way to get runtime environment variables.
	// Reference: https://caddyserver.com/docs/caddyfile/concepts#environment-variables
	//
	// So, with this, it should be able to do something like this:
	// ```
	// api_token {env.CLOUDFLARE_API_TOKEN}
	// ```
	// which would replace `{env.CLOUDFLARE_API_TOKEN}` with the environemnt variable value
	// of CLOUDFLARE_API_TOKEN at runtime.
	s.APIToken = caddy.NewReplacer().ReplaceAll(s.APIToken, "")
	s.AccountID = caddy.NewReplacer().ReplaceAll(s.AccountID, "")
	s.NamespaceID = caddy.NewReplacer().ReplaceAll(s.NamespaceID, "")

	if s.APIToken == "" {
		return fmt.Errorf("api_token must be provided and not empty")
	}

	if s.AccountID == "" {
		return fmt.Errorf("account_id must be provided and not empty")
	}

	if s.NamespaceID == "" {
		return fmt.Errorf("namespace_id must be provided and not empty")
	}

	s.client = cloudflare.NewClient(
		option.WithAPIToken(s.APIToken),
	)

	kv, err := s.client.KV.Namespaces.Get(s.ctx, s.NamespaceID, kv.NamespaceGetParams{
		AccountID: cloudflare.F(s.AccountID),
	})

	if err != nil {
		return fmt.Errorf("failed to verify Cloudflare KV namespace '%s': %v", s.NamespaceID, err)
	}

	if kv.ID == "" {
		return fmt.Errorf("Cloudflare KV namespace '%s' not found", s.NamespaceID)
	}

	s.Logger.Infof("Cloudflare KV Storage initialized for namespace %s'", s.NamespaceID)

	return nil
}

func (s *CloudflareKVStorage) Store(_ context.Context, key string, value []byte) error {
	s.Logger.Infof("Storing key '%s'", key)

	metadata := &Metadata{
		Modified: time.Now(),
	}
	serializedMetadata, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("unable to encode metadata for key %s: %v", key, err)
	}

	encodedValue := base64.StdEncoding.EncodeToString(value)

	_, err = s.client.KV.Namespaces.Values.Update(s.ctx, s.NamespaceID, key, kv.NamespaceValueUpdateParams{
		AccountID: cloudflare.F(s.AccountID),
		Metadata:  cloudflare.F(string(serializedMetadata)),
		Value:     cloudflare.F(encodedValue),
	})
	if err != nil {
		return fmt.Errorf("failed to write KV entry: %v", err)
	}

	return nil
}

func (s *CloudflareKVStorage) Load(_ context.Context, key string) ([]byte, error) {
	s.Logger.Infof("Attempting to load key: %s", key)

	resp, err := s.client.KV.Namespaces.Values.Get(s.ctx, s.NamespaceID, key, kv.NamespaceValueGetParams{
		AccountID: cloudflare.F(s.AccountID),
	})
	defer resp.Body.Close()
	if err != nil {
		if resp.StatusCode == 404 {
			return nil, fs.ErrNotExist
		}

		return nil, err
	}

	val, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Cloudflare responded with %s: %s", resp.Status, val)
	}

	var responseData LoadValueResponse
	err = json.Unmarshal(val, &responseData)
	if err != nil {
		return nil, err
	}

	decodedValue, err := base64.StdEncoding.DecodeString(responseData.Value)
	if err != nil {
		return nil, err
	}

	return decodedValue, nil
}

func (s *CloudflareKVStorage) Delete(ctx context.Context, key string) error {
	s.Logger.Infof("Deleting key '%s'", key)

	_, err := s.client.KV.Namespaces.Values.Delete(s.ctx, s.NamespaceID, key, kv.NamespaceValueDeleteParams{
		AccountID: cloudflare.F(s.AccountID),
	})
	if err != nil {
		return fmt.Errorf("failed to delete KV entry: %v", err)
	}

	return nil
}

func (s *CloudflareKVStorage) Exists(ctx context.Context, key string) bool {
	_, err := s.Load(ctx, key)
	return err == nil
}

func (s *CloudflareKVStorage) List(_ context.Context, path string, recursive bool) ([]string, error) {
	var allKeys []string

	resp := s.client.KV.Namespaces.Keys.ListAutoPaging(s.ctx, s.NamespaceID, kv.NamespaceKeyListParams{
		AccountID: cloudflare.F(s.AccountID),
	})
	if resp.Err() != nil {
		return nil, fmt.Errorf("error listing keys with prefix '%s': %v", path, resp.Err())
	}

	for resp.Next() {
		key := resp.Current()
		allKeys = append(allKeys, key.Name)
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

func (s *CloudflareKVStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	dataBytes, err := s.Load(ctx, key)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	metadataMap, err := s.client.KV.Namespaces.Metadata.Get(s.ctx, s.NamespaceID, key, kv.NamespaceMetadataGetParams{
		AccountID: cloudflare.String(s.AccountID),
	})
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	metadataMapJson, err := json.Marshal(metadataMap)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	var data Metadata
	if err := json.Unmarshal(metadataMapJson, &data); err != nil {
		return certmagic.KeyInfo{}, fmt.Errorf("unable to decode data for key %s: %v", key, err)
	}

	return certmagic.KeyInfo{
		Key:        key,
		Modified:   data.Modified,
		Size:       int64(len(dataBytes)),
		IsTerminal: true,
	}, nil
}

func (s *CloudflareKVStorage) Lock(ctx context.Context, key string) error {
	return nil
}

func (s *CloudflareKVStorage) Unlock(_ context.Context, key string) error {
	return nil
}

func (s CloudflareKVStorage) String() string {
	type Redacted CloudflareKVStorage

	r := Redacted(s)
	r.APIToken = "REDACTED"

	out, _ := json.Marshal(r)
	return string(out)
}
