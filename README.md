# Minecraft Configuration Auditor

Minecraft Configuration Auditor is a serious personal open-source project for reviewing Java server configuration safely before a change is made. It reads synthetic `server.properties`, `paper-global.yml`, or `spigot.yml` files and produces a deterministic JSON or Markdown report.

## What it checks

- authentication and secure player-profile settings;
- whitelist and operator-facing exposure;
- RCON/query enablement and port validity;
- conservative view/simulation distance settings;
- placeholder RCON secrets and disabled compression;
- source file and line numbers for each finding.

The project is **not** a vulnerability scanner, server monitor, or production guarantee. It is an offline, read-only review tool. It uses no network, credentials, private data, or client systems.

## Run it

```text
npm test
node src/cli.mjs fixtures/insecure --format markdown
node src/cli.mjs fixtures/balanced --format json
```

The insecure fixture is deliberately synthetic and contains a fake placeholder password. Never copy fixture credentials into a real server.

## Engineering notes

The auditor fails closed when authentication is missing, keeps rules as small explainable functions, records evidence and remediation separately, and sorts output deterministically for review and CI. See [the threat model](docs/threat-model.md) for boundaries and limitations.

## License

MIT. See [LICENSE](LICENSE).

