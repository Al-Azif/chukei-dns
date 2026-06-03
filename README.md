![Logo](logo.png?raw=true)
=====

> Peace comes from within. Do not seek it without.

## Synopsis

Chūkei DNS is a lightweight DNS __relay__ server. It provides DNS-over-HTTPS (DoH) functionality to bypass DNS hijacking by ISPs and other network intermediaries while offering domain filtering capabilities to block unwanted connections like system updates and telemetry.

### Primary Use Case
On PlayStation®4/PlayStation®5 systems, Chūkei DNS integrates as a plugin within HEN payloads. By setting the console's DNS to `127.0.0.1`, the system cannot resolve domain names until a payload containing Chūkei DNS is executed. Once active, DNS resolution is restored with filtering and DoH protection enabled.

## Another Use Case
Access unofficial Minecraft servers on a PlayStation®4/PlayStation®5 system. EarthOnion hosts a community Minecraft server that can be accessed by adding the following entry to your `zones.json` file:

```json
{
  "zone": "hivebedrock.network.",
  "records": [
    { "name": "@", "type": "A", "ttl": 300, "data": "139.162.113.175" },
    { "name": "*", "type": "A", "ttl": 300, "data": "139.162.113.175" }
  ]
},
{
  "zone": "inpvp.net.",
  "records": [
    { "name": "@", "type": "A", "ttl": 300, "data": "139.162.113.175" },
    { "name": "*", "type": "A", "ttl": 300, "data": "139.162.113.175" }
  ]
},
{
  "zone": "lbsg.net.",
  "records": [
    { "name": "@", "type": "A", "ttl": 300, "data": "139.162.113.175" },
    { "name": "*", "type": "A", "ttl": 300, "data": "139.162.113.175" }
  ]
},
{
  "zone": "galaxite.net.",
  "records": [
    { "name": "@", "type": "A", "ttl": 300, "data": "139.162.113.175" },
    { "name": "*", "type": "A", "ttl": 300, "data": "139.162.113.175" }
  ]
},
{
  "zone": "enchanted.gg.",
  "records": [
    { "name": "@", "type": "A", "ttl": 300, "data": "139.162.113.175" },
    { "name": "*", "type": "A", "ttl": 300, "data": "139.162.113.175" }
  ]
}
```

### Cross-Platform Support
PC builds are available for development, testing, and general use.
Console builds are compatible with all firmwares supported by the SDK; the server behavior is not firmware-dependent.

**TL;DR:** A locally hosted DNS-over-HTTPS (DoH) relay with domain filtering and man-in-the-middle capabilities built-in.

---

## Features

- **DNS-over-HTTPS relay** - Forwards unmatched queries upstream via RFC 8484 DoH (HTTP POST or GET)
- **UDP and TCP transport** - Listens on both UDP and TCP on the same port per RFC 1035 §4.2; TCP supports multiple pipelined queries per connection
- **Domain filtering** - Returns NXDOMAIN for domains marked `{{BLOCKED}}`
- **Domain hijacking / redirection** - Returns custom A/AAAA records, including `{{SELF}}` (the server's own redirect IP)
- **Selective forwarding** - `{{FORWARD}}` skips local DNS for specific subdomains; `{{FORWARD_ALL}}` includes sub-subdomains of that subdomain
- **Regex-based zone matching** - Subdomain keys in `zones.json` are treated as regular expressions
- **In-memory DNS cache** - Caches upstream DoH responses, respects TTLs, and transparently rewrites TTLs and transaction IDs on cache hits
- **Multi-resolver failover** - Shuffles and retries across configured DoH resolvers on failure
- **Supported record types** - A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV
- **RFC-compliant error responses** - FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED
- **EDNS0 OPT record acknowledgment** - OPT records are recognized, however only `COOKIE` is implemented
- **Graceful shutdown** - Handles SIGINT / SIGTERM
- **Server socket auto-recovery** - UDP and TCP sockets automatically reopen after fatal errors (e.g., bad descriptor) with retry backoff
- **Configurable DoH timeout budget** - Global timeout across all resolver attempts prevents worst-case multi-resolver latency
- **Built-in default zones** - Falls back to compiled-in zone rules when `zones.json` is missing or invalid

---

## Requirements

### PC
- CMake >= 3.10.2
- Clang >= 18
- make

### PlayStation®4 (Orbis)
- [PS4 Payload Dev SDK](https://github.com/ps4-payload-dev/sdk)

### PlayStation®5 (Prospero)
- [PS5 Payload Dev SDK](https://github.com/ps5-payload-dev/sdk)

---

## How to Build

### PC - Debug
```sh
cmake -DCMAKE_BUILD_TYPE=Debug .
make -j$(nproc)
```

### PC - Release
```sh
cmake -DCMAKE_BUILD_TYPE=Release .
make -j$(nproc)
```

### PlayStation®4
```sh
$PS4_PAYLOAD_SDK/bin/orbis-cmake -DCMAKE_BUILD_TYPE=Release .
make -j$(nproc)
```

### PlayStation®5
```sh
$PS5_PAYLOAD_SDK/bin/prospero-cmake -DCMAKE_BUILD_TYPE=Release .
make -j$(nproc)
```

The binary is placed in `build/bin/`.

---

## Configuration

### Zones File (`zones.json`)

The server loads `zones.json` from the working directory at startup. If the file is missing or invalid it falls back to internal compiled-in defaults. A JSON schema is available in `zones-schema.jsonc`.

The file contains a top-level `zones` array. Each element is a zone object with the following fields:

| Field     | Type    | Required | Description                                                    |
|-----------|---------|----------|----------------------------------------------------------------|
| `zone`    | string  | yes      | Root domain (FQDN with trailing dot, e.g. `"example.com."`)    |
| `regex`   | boolean | no       | If `true`, `zone` is treated as a regular expression           |
| `blocked` | boolean | no       | If `true`, all queries for this zone return NXDOMAIN           |
| `records` | array   | no*      | DNS records for this zone (* required when `blocked` is false) |

Each record object in the `records` array:

| Field   | Type    | Required | Description                                                                                    |
|---------|---------|----------|------------------------------------------------------------------------------------------------|
| `name`  | string  | yes      | Zone-relative name: `"@"` (root), `"*"` (wildcard), or subdomain (e.g. `"www"`, `"ctest.cdn"`) |
| `regex` | boolean | no       | If `true`, `name` is treated as a regular expression                                           |
| `type`  | string  | yes      | Record type: `A`, `AAAA`, `NS`, `CNAME`, `SOA`, `TXT`, `MX`, `SRV`, `PTR`                      |
| `ttl`   | integer | yes      | Time-to-live in seconds (0-604800)                                                             |
| `data`  | varies  | yes      | Record data (format depends on `type`, see below)                                              |

**Record data formats by type:**

| Type    | `data` format                                                                       |
|---------|-------------------------------------------------------------------------------------|
| `A`     | IPv4 string, `"{{SELF}}"`, `"{{BLOCKED}}"`, `"{{FORWARD}}"`, or `"{{FORWARD_ALL}}"` |
| `AAAA`  | IPv6 string, `"{{SELF}}"`, `"{{BLOCKED}}"`, `"{{FORWARD}}"`, or `"{{FORWARD_ALL}}"` |
| `NS`    | Domain name string                                                                  |
| `CNAME` | Domain name string                                                                  |
| `PTR`   | Domain name string                                                                  |
| `TXT`   | Array of strings                                                                    |
| `SOA`   | Object: `{ "primary", "admin", "serial", "refresh", "retry", "expire", "minimum" }` |
| `MX`    | Object: `{ "preference": int, "exchange": string }`                                 |
| `SRV`   | Object: `{ "priority": int, "weight": int, "port": int, "target": string }`         |

**Example:**

```json
{
  "zones": [
    {
      "zone": "example.com.",
      "records": [
        { "name": "@", "type": "A", "ttl": 300, "data": "192.0.2.1" },
        { "name": "*", "type": "A", "ttl": 300, "data": "{{BLOCKED}}" },
        { "name": "www", "type": "A", "ttl": 300, "data": "{{SELF}}" },
        { "name": "api", "type": "A", "ttl": 300, "data": "{{FORWARD}}" },
        { "name": "cdn", "type": "A", "ttl": 300, "data": "{{FORWARD_ALL}}" },
        { "name": "cdn", "type": "CNAME", "ttl": 300, "data": "cdn.example.net." }
      ]
    },
    {
      "zone": "ads.example.net.",
      "blocked": true
    },
    {
      "zone": "playstation.net.",
      "records": [
        { "name": "d(jp|us|eu)01\\.(ps4|ps5)\\.update", "regex": true, "type": "A", "ttl": 300, "data": "{{SELF}}" }
      ]
    }
  ]
}
```

**Special values:**

| Value               | Meaning                                                                                                                                                                                                                 |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `"{{BLOCKED}}"`     | Zone-level: return NXDOMAIN for the entire domain. Record-level (A/AAAA): sinkhole to `0.0.0.0` / `::`                                                                                                                  |
| `"{{SELF}}"`        | Redirect to the server's configured redirect IP (default `127.0.0.1` / `::1`)                                                                                                                                           |
| `"{{FORWARD}}"`     | Skip local DNS and forward the query to the upstream DoH resolver                                                                                                                                                       |
| `"{{FORWARD_ALL}}"` | Like `{{FORWARD}}`, but also forwards all sub-subdomains of the matched name. For example, `"api"` with `{{FORWARD_ALL}}` forwards `api.zone`, `test.api.zone`, etc. - but not `different.zone` or the bare root domain |

> **Note:** The wildcard `"*"` only matches subdomains - it never matches the bare root domain (`"@"`). For example, if only `"*"` is defined and `"@"` is not, queries for the root domain will be forwarded to DoH.

### CLI Options (PC only)

```
Usage: ./build/bin/main [options]

Options:
  --log-level <level>     Log level: none, fatal, error, warn, info, debug, trace, all (default: info)
  --doh-only              Enable DoH-only mode (no local zone responses)
  --doh-resolver <url>    DoH resolver URL (can be specified multiple times)
  --doh-timeout <ms>      Total timeout budget for DoH resolution (default: 15000)
  --user-agent <string>   User-Agent string for DoH requests
  --cacert <path>         Path to a PEM CA certificate bundle for TLS verification
  --zones <path>          Path to the zones.json file (default: ./zones.json)
  --dns-ip <ip>           IP address for the DNS server (default: 127.0.0.1)
  --dns-port <port>       Port for the DNS server (default: 53, range: 1-65535)
  --redirect-ipv4 <ip>    IPv4 address for redirection (default: 127.0.0.1)
  --redirect-ipv6 <ip>    IPv6 address for redirection (default: ::1)
  --ttl <seconds>         Default TTL for DNS responses (default: 3600, range: 0-604800)
  --help                  Display help message
```

| Option                  | Description                                                                                  | Default        |
|-------------------------|----------------------------------------------------------------------------------------------|----------------|
| `--log-level <level>`   | Minimum log level to emit: `none`, `fatal`, `error`, `warn`, `info`, `debug`, `trace`, `all` | `info`         |
| `--doh-only`            | Skip local zone lookups; forward everything to DoH resolvers                                 | off            |
| `--doh-resolver <url>`  | Add a DoH resolver URL (repeatable; replaces built-in list when used)                        | built-in list  |
| `--doh-timeout <ms>`    | Total timeout budget for all DoH resolver attempts (100-60000 ms)                            | `15000`        |
| `--user-agent <string>` | Custom `User-Agent` header for outgoing DoH requests                                         | auto-generated |
| `--cacert <path>`       | Path to a PEM CA certificate bundle for TLS verification                                     | system default |
| `--zones <path>`        | Path to the `zones.json` file                                                                | `./zones.json` |
| `--dns-ip <ip>`         | IP address the UDP and TCP listeners bind to                                                 | `127.0.0.1`    |
| `--dns-port <port>`     | Port the UDP and TCP listeners bind to (1-65535)                                             | `53`           |
| `--redirect-ipv4 <ip>`  | IPv4 address returned for `{{SELF}}` records                                                 | `127.0.0.1`    |
| `--redirect-ipv6 <ip>`  | IPv6 address returned for `{{SELF}}` records                                                 | `::1`          |
| `--ttl <seconds>`       | Default TTL for DNS responses (0-604800)                                                     | `3600`         |
| `--help`                | Print usage information and exit                                                             | N/A            |

### PlayStation®4/PlayStation®5 Configuration (`config.json`)

On console platforms, settings are loaded from a JSON configuration file at `/data/chukei/config.json`. All keys are optional - missing keys fall back to built-in defaults. If the file does not exist, the server starts with defaults.

An example configuration file is provided in `config.example.json`.

| Key              | Type    | Description                                                                                  | Default                   |
|------------------|---------|----------------------------------------------------------------------------------------------|---------------------------|
| `log_level`      | string  | Minimum log level to emit: `none`, `fatal`, `error`, `warn`, `info`, `debug`, `trace`, `all` | `info`                    |
| `doh_only`       | boolean | Skip local zone lookups; forward everything to DoH resolvers                                 | `false`                   |
| `doh_resolvers`  | array   | List of DoH resolver URLs (replaces built-in list when set)                                  | built-in list             |
| `doh_timeout_ms` | integer | Total timeout budget for all DoH resolver attempts (100-60000 ms)                            | `15000`                   |
| `user_agent`     | string  | Custom `User-Agent` header for outgoing DoH requests                                         | auto-generated            |
| `cacert_path`    | string  | Path to a PEM CA certificate bundle for TLS verification                                     | `/data/chukei/cacert.pem` |
| `zones_path`     | string  | Path to the `zones.json` file                                                                | `/data/chukei/zones.json` |
| `dns_ip`         | string  | IP address the UDP and TCP listeners bind to                                                 | `127.0.0.1`               |
| `dns_port`       | integer | Port the UDP and TCP listeners bind to (1-65535)                                             | `53`                      |
| `redirect_ipv4`  | string  | IPv4 address returned for `{{SELF}}` records                                                 | `127.0.0.1`               |
| `redirect_ipv6`  | string  | IPv6 address returned for `{{SELF}}` records                                                 | `::1`                     |
| `ttl`            | integer | Default TTL for DNS responses (0-604800)                                                     | `3600`                    |

> **User-Agent template tokens:** `{{APP_VERSION}}`, `{{APP_DESCRIPTION}}`, `{{APP_HOMEPAGE}}`, `{{CONSOLE}}`, `{{FIRMWARE_VERSION}}`
>
> Example defaults: `chukei/{{APP_VERSION}} ({{CONSOLE}})` on desktop, or `chukei/{{APP_VERSION}} ({{CONSOLE}} {{FIRMWARE_VERSION}})` on console builds.

**Console file layout:**

```
/data/chukei/
├── config.json    # Runtime configuration (optional)
├── zones.json     # Zone rules
└── cacert.pem     # CA certificate bundle for TLS verification
```

> **Note:** When no external CA certificate is provided, console builds use a Mozilla CA bundle that is embedded at compile time.

### Default DoH Resolvers

The following resolvers are built in (used when no custom resolvers are configured):

| Resolver               | URL                         |
|------------------------|-----------------------------|
| Cloudflare (primary)   | `https://1.1.1.1/dns-query` |
| Cloudflare (secondary) | `https://1.0.0.1/dns-query` |
| Google (primary)       | `https://8.8.8.8/dns-query` |
| Google (secondary)     | `https://8.8.4.4/dns-query` |
| Quad9                  | `https://9.9.9.9/dns-query` |

By default, Cloudflare primary and secondary are active. Resolvers are shuffled per request and the next resolver is tried automatically on failure.

---

## Architecture

```
Client
    │  DNS query (UDP or TCP wire format)
    ▼
UdpServer / TcpServer - ASIO listeners on configured IP:port
    │                   (TCP uses 2-byte length prefix per RFC 1035 §4.2.2)
    │
    ├── DnsParser     - Parses wire-format packet; extracts domain, subdomain, record type
    │
    ├── LocalDns      - Matches against zones.json rules (regex subdomain matching)
    │                   returns A/AAAA/CNAME/MX/TXT/SRV/NS/SOA/PTR responses or
    │                   NXDOMAIN/BLOCKED
    │
    ├── DnsCache      - In-memory TTL cache keyed by (domain, qtype) rewrites transaction
    │                   ID and adjusts TTLs on hits
    │
    └── DnsOverHttps  - libcurl multi-handle DoH client (RFC 8484) shuffles resolvers,
                        retries on failure, supports POST and GET
```

**Source layout:**

| File                    | Responsibility                                                                 |
|-------------------------|--------------------------------------------------------------------------------|
| `src/main-pc.cc`        | PC entry point: CLI argument parsing, ASIO event loop, signal handling         |
| `src/main-ps.cc`        | PlayStation entry point: loads `/data/chukei/config.json`, ASIO event loop     |
| `src/config.cc`         | Global `Config` object with validated setters                                  |
| `src/config_parser.cc`  | JSON zones file parsing; compile-time default fallback                         |
| `src/dns_cache.cc`      | LRU / TTL-expiry cache with TTL rewrite on cache hit                           |
| `src/dns_over_https.cc` | RFC 8484 DoH client using libcurl with HTTP/2 multiplexing                     |
| `src/dns_packet*.cc`    | `DnsHeader`, `DnsQuestion`, `DnsAnswer`, `DnsRequestPacket` classes (RFC 1035) |
| `src/dns_parser.cc`     | Wire-format DNS packet parsing; domain part extraction                         |
| `src/dns_response.cc`   | Response builders for all supported record types and error codes               |
| `src/local_dns.cc`      | Zone lookup with regex subdomain matching, reverse-IP helpers                  |
| `src/udp_server.cc`     | UDP receive/send loop, query dispatch                                          |
| `src/tcp_server.cc`     | TCP accept/session loop, 2-byte length-prefixed framing, query dispatch        |
| `src/utils.cc`          | IPv4/IPv6 binary conversion, endian helpers, OS version detection              |

**External dependencies (in `external/`):**

All dependencies are fully vendored - no system libraries are required. This means the project cross-compiles cleanly for PS4/PS5 toolchains without any host package installation.

| Library                                           | Purpose                                            |
|---------------------------------------------------|----------------------------------------------------|
| [ASIO](https://think-async.com/Asio/)             | Standalone async networking (header-only)          |
| [banned.h](https://github.com/nicowillis/banned)  | SDL-recommended unsafe function list (header-only) |
| [curl](https://curl.se/libcurl/)                  | HTTPS transport for DoH (built from source)        |
| [libLog](https://github.com/Al-Azif/libLog)       | Logging (PC, PS4, PS5)                             |
| [nlohmann/json](https://github.com/nlohmann/json) | JSON parsing (header-only)                         |
| [wolfSSL](https://www.wolfssl.com/)               | TLS backend for curl (built from source)           |

---

## Query Resolution Flow

1. Receive packet (UDP) or read length-prefixed message (TCP)
2. Parse and validate DNS packet
3. Reject non-standard opcodes with NOTIMP (RFC 1035 §4.1.1)
4. If not in DoH-only mode -> check local zones (`zones.json`)
5. On local miss -> check in-memory DNS cache
6. On cache miss -> forward to DoH resolver (with automatic failover)
7. Cache successful DoH response
8. If DoH fails -> respond SERVFAIL
9. If no match at all -> respond NXDOMAIN

---

## Testing

### Unit Tests
Built with `-DBUILD_TESTS=ON`. Uses a minimal custom test framework (no external dependencies, compatible with PS4/PS5/PC).

```sh
cmake -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug .
make -j$(nproc)
./build/bin/run_tests
```

### Integration Tests

A Python 3 script (`tests/integration_test.py`) exercises the server binary end-to-end. It automatically starts the server on a high port (`15353`), sends raw DNS queries over both UDP and TCP, verifies responses, and shuts the server down when finished.

**Prerequisites:** the project must be built first (the script expects `build/bin/main` and `zones.json` to exist).

```sh
# Run integration tests (starts and stops the server automatically)
python3 tests/integration_test.py
```

The script manages the full server lifecycle - no manual start/stop is required. On completion (or on failure) it sends `SIGTERM` to the server process. If the server does not exit within 5 seconds it is forcefully killed.

If you need to run the server manually for ad-hoc testing instead:

```sh
# Start the server on a non-privileged port
./build/bin/main --dns-port 15353 &
SERVER_PID=$!

# ... run your tests ...

# Stop the server when done
kill "$SERVER_PID"
```

---

## Notes

- Not meant for production use by any means. It targets local, single-client scenarios - not a full DNS server.
- The zones file format is subject to change at any time.
- Console builds load settings from `/data/chukei/config.json` at startup; missing keys fall back to built-in defaults.
- A missing, unreadable, or unparseable `/data/chukei/config.json` causes the server to load built-in safe default settings.
- A missing, unreadable, or unparseable `/data/chukei/zones.json` causes the server to load built-in safe default rules.
- Hot-reloading of `/data/chukei/config.json` and/or `/data/chukei/zones.json` is not supported; a restart is required to load changes. Starting another instance of Chūkei DNS will terminate any currently running Chūkei DNS instances and reload the config/zones.
- PC builds accept CLI flags for all major settings (run `./build/bin/main --help` to list them).
- Blocked-domain NXDOMAIN responses include a synthetic SOA in the authority section when the zone name is known. The fallback NXDOMAIN (no zone context) intentionally remains without SOA since the server isn't authoritative for unknown domains.

---

## License

GPLv3. See [LICENSE](LICENSE).
