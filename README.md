# DNS Server In A Weekend

This is a toy implementation of a DNS server that follows the [Implement DNS in a weekend](https://implement-dns.wizardzines.com/index.html) guide.

## Usage

Start the DNS server at port `5354`:
```sh
RUST_LOG=info dns-in-a-weekend --port 5354
```

Make a DNS request with `dig` to test that it is accessible:
```sh
dig @127.0.0.1 -p 5354 google.com
```

If `dig` prints the DNS response, it means everything is working.

## Development

### Install

#### Via `cargo`
```sh
cargo install dns-in-a-weekend
```

### Build

Checkout the project and run if you have cargo already set up.
```sh
cargo build --release
```

## Features

#### Caching

It implements caching of DNS resolutions so that we don't overwhelm the root name servers.

**Caveat**: The cache has no TTL so it could go stale (even though the `DNSRecord`s themselves have TTLs we don't implement it here).
