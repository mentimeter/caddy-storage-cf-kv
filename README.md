# Caddy Storate Cloudflare KV

Use [Cloudflare KV](https://developers.cloudflare.com/api/resources/kv/) as [Caddy storage](https://caddyserver.com/docs/json/storage/).

### Build custom Caddy with this storage

```bash
xcaddy build --with github.com/mentimeter/caddy-storage-cf-kv
```

### Token required permissions
- Workers KV Storage Read
- Workers KV Storage Write

### Setup Caddyfile

```
{
    storage cloudflare_kv {
        api_token "<TOKEN>"
        account_id "<ACCOUNT_ID>"
        namespace_id "<NAMESPACE_ID>"
    }
}
```

or using environment variables

```
{
    storage cloudflare_kv {
        api_token "{env.CLOUDFLARE_API_TOKEN}"
        account_id "{env.CLOUDFLARE_ACCOUNT_ID}"
        namespace_id "{env.CLOUDFLARE_NAMESPACE}"
    }
}
```

which will replace `{env.CLOUDFLARE_API_TOKEN}`, `{env.CLOUDFLARE_ACCOUNT_ID}`
and `{env.CLOUDFLARE_NAMESPACE}` with the equivalent `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_NAMESPACE` environment variables [at runtime](https://caddyserver.com/docs/caddyfile/concepts#environment-variables).

For example, running with Cloudflare as the DNS resolver (using https://github.com/caddy-dns/cloudflare) and storage for the created TLS certificates.

```
{
    http_port 80
    https_port 443

    storage cloudflare_kv {
        api_token "{env.CLOUDFLARE_API_TOKEN}"
        account_id "{env.CLOUDFLARE_ACCOUNT_ID}"
        namespace_id "{env.CLOUDFLARE_NAMESPACE}"
    }
}

example.org, *.example.org {
    reverse_proxy localhost:3000

    tls {
        dns cloudflare {env.CLOUDFLARE_API_TOKEN}
    }
}
```