# Threat model and ethical scope

Minecraft Configuration Auditor is intentionally **offline and read-only**. It reads local fixture files, reports explainable findings, and never connects to a server, scans an address, changes a configuration, or handles a credential.

The rules focus on defensive hygiene: authentication mode, secure profiles, whitelist posture, exposed RCON/query services, conservative distance settings, and placeholder secrets. A finding is a prompt for review, not a claim that a server is exploitable or safe.

For a real deployment, an operator should review proxy forwarding, firewall policy, plugins/mods, backups, patch level, permissions, and measured performance with the server owner. Those checks are deliberately outside this small reference implementation.
