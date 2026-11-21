# Izena PowerDNS connector

A WASI connector for PowerDNS Authoritative 5.x. It manages zones, RRsets,
DNSSEC, and SOA serial policies through Izena. Set `PDNS_VERSION=5.0` or
`PDNS_VERSION=5.1` to select the integration fixture.

## Development

```sh
make test
make test-integration-fixtures
make build
```

`make build` writes the Wasm artifact and its `.sha256` file. Run
`make artifact-path` for the artifact path and `make help` for other commands.

## License

[Apache License 2.0](LICENSE)
