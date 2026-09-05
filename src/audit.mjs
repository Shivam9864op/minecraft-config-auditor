import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export function parseProperties(text) {
  const values = {};
  const sources = {};
  String(text).split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) return;
    const separator = trimmed.indexOf('=');
    if (separator < 1) return;
    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim();
    values[key] = value;
    sources[key] = { file: 'server.properties', line: index + 1 };
  });
  return { values, sources };
}

function scalar(value) {
  const trimmed = value.trim().replace(/^['"]|['"]$/g, '');
  if (/^(true|false)$/i.test(trimmed)) return trimmed.toLowerCase() === 'true';
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) return Number(trimmed);
  return trimmed;
}

export function parseSimpleYaml(text, file = 'paper-global.yml') {
  const values = {};
  const sources = {};
  const stack = [];
  String(text).split(/\r?\n/).forEach((line, index) => {
    if (!line.trim() || line.trim().startsWith('#')) return;
    const indent = line.length - line.trimStart().length;
    const match = line.trim().match(/^([^:#][^:]*):\s*(.*)$/);
    if (!match) return;
    while (stack.length && stack.at(-1).indent >= indent) stack.pop();
    const key = match[1].trim();
    const path = [...stack.map((item) => item.key), key].join('.');
    if (match[2].trim() === '') stack.push({ indent, key });
    else {
      values[path] = scalar(match[2]);
      sources[path] = { file, line: index + 1 };
    }
  });
  return { values, sources };
}

function bool(values, key) {
  const value = values[key];
  return value === true || String(value).toLowerCase() === 'true';
}

function number(values, key) {
  const value = Number(values[key]);
  return Number.isFinite(value) ? value : null;
}

function finding(id, severity, title, evidence, remediation, source) {
  return { id, severity, title, evidence, remediation, source: source ?? null };
}

export function auditValues(values, sources = {}) {
  const findings = [];
  const source = (key) => sources[key] ?? null;
  const serverPort = number(values, 'server-port');
  if (serverPort === null || serverPort < 1 || serverPort > 65535) {
    findings.push(finding('CFG-001', 'high', 'Server port is invalid', `server-port=${values['server-port'] ?? 'missing'}`, 'Use a TCP port from 1 to 65535 and keep firewall exposure intentional.', source('server-port')));
  }
  if (!bool(values, 'online-mode')) {
    findings.push(finding('SEC-001', 'critical', 'Online-mode authentication is disabled', `online-mode=${values['online-mode'] ?? 'missing'}`, 'Enable online-mode unless this is a documented, isolated test environment. Never expose an unauthenticated server to the public internet.', source('online-mode')));
  }
  if (!bool(values, 'enforce-secure-profile')) {
    findings.push(finding('SEC-002', 'medium', 'Secure player profiles are not enforced', `enforce-secure-profile=${values['enforce-secure-profile'] ?? 'missing'}`, 'Enable secure-profile enforcement on modern Java servers unless a compatibility exception is documented.', source('enforce-secure-profile')));
  }
  if (!bool(values, 'white-list')) {
    findings.push(finding('SEC-003', 'medium', 'Whitelist is disabled', `white-list=${values['white-list'] ?? 'missing'}`, 'Enable the whitelist for private or staff-managed servers and review operators regularly.', source('white-list')));
  }
  if (bool(values, 'enable-rcon')) {
    findings.push(finding('SEC-004', 'high', 'RCON is enabled', 'enable-rcon=true', 'Disable RCON unless it is required. If required, bind it privately, rotate its password, and restrict access at the network layer.', source('enable-rcon')));
  }
  if (bool(values, 'enable-query')) {
    const queryPort = number(values, 'query.port');
    if (queryPort === null || queryPort < 1 || queryPort > 65535) {
      findings.push(finding('CFG-002', 'high', 'Query is enabled with an invalid port', `enable-query=true; query.port=${values['query.port'] ?? 'missing'}`, 'Set a valid query port or disable query when it is not needed.', source('query.port')));
    } else {
      findings.push(finding('OPS-001', 'info', 'Query service is enabled', `query.port=${queryPort}`, 'Confirm that the query port is intentionally exposed and monitored.', source('enable-query')));
    }
  }
  const viewDistance = number(values, 'view-distance');
  if (viewDistance !== null && (viewDistance < 4 || viewDistance > 16)) {
    findings.push(finding('PERF-001', 'low', 'View distance is outside a conservative range', `view-distance=${viewDistance}`, 'Start around 6–12 and adjust after measuring tick time and player experience.', source('view-distance')));
  }
  const simulationDistance = number(values, 'simulation-distance');
  if (simulationDistance !== null && (simulationDistance < 4 || simulationDistance > 12)) {
    findings.push(finding('PERF-002', 'low', 'Simulation distance may increase tick cost', `simulation-distance=${simulationDistance}`, 'Start around 6–10 and validate with measured timings before increasing it.', source('simulation-distance')));
  }
  if (String(values['network-compression-threshold'] ?? '') === '0') {
    findings.push(finding('PERF-003', 'low', 'Network compression is disabled', 'network-compression-threshold=0', 'Use the server default unless a measured compatibility reason requires disabling compression.', source('network-compression-threshold')));
  }
  if (values['rcon.password'] && /change[-_ ]?me|example|placeholder/i.test(String(values['rcon.password']))) {
    findings.push(finding('SEC-005', 'high', 'RCON password is a fixture placeholder', 'rcon.password looks like a placeholder', 'Set secrets outside configuration fixtures and rotate any credential that was ever committed.', source('rcon.password')));
  }
  findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.id.localeCompare(b.id));
  return findings;
}

export async function auditDirectory(directory) {
  const baseDirectory = directory instanceof URL ? fileURLToPath(directory) : directory;
  const values = {};
  const sources = {};
  const files = [];
  for (const [name, parser] of [['server.properties', parseProperties], ['paper-global.yml', parseSimpleYaml], ['spigot.yml', parseSimpleYaml]]) {
    try {
      const text = await readFile(join(baseDirectory, name), 'utf8');
      const parsed = parser(text, name);
      Object.assign(values, parsed.values);
      Object.assign(sources, parsed.sources);
      files.push(name);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  const findings = auditValues(values, sources);
  const summary = Object.fromEntries(SEVERITIES.map((severity) => [severity, findings.filter((item) => item.severity === severity).length]));
  return { directory: baseDirectory, files, summary: { ...summary, total: findings.length }, findings };
}

export function renderMarkdown(report) {
  const lines = [
    '# Minecraft configuration audit',
    '',
    `- **Fixture:** \`${report.directory}\``,
    `- **Files read:** ${report.files.length ? report.files.join(', ') : 'none'}`,
    `- **Findings:** ${report.summary.total} (critical ${report.summary.critical}, high ${report.summary.high}, medium ${report.summary.medium}, low ${report.summary.low}, info ${report.summary.info})`,
    '',
    '> This is a read-only offline audit. It does not connect to a server, change files, or prove that a configuration is safe in every environment.',
    ''
  ];
  if (!report.findings.length) lines.push('No findings for the rules enabled in this demo.');
  for (const item of report.findings) {
    lines.push(`## ${item.id} — ${item.severity.toUpperCase()}: ${item.title}`, '', `**Evidence:** ${item.evidence}`, '', `**Recommendation:** ${item.remediation}`, '');
    if (item.source) lines.push(`**Source:** ${item.source.file}:${item.source.line}`, '');
  }
  return `${lines.join('\n').trim()}\n`;
}
