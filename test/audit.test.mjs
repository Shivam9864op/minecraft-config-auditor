import assert from 'node:assert/strict';
import test from 'node:test';
import { auditDirectory, auditValues, parseProperties, parseSimpleYaml, renderMarkdown } from '../src/audit.mjs';

const root = new URL('../fixtures/', import.meta.url);

test('properties parsing records values and line numbers', () => {
  const parsed = parseProperties('# comment\nserver-port=25565\nwhite-list=true\ninvalid-line');
  assert.equal(parsed.values['server-port'], '25565');
  assert.deepEqual(parsed.sources['white-list'], { file: 'server.properties', line: 3 });
});

test('simple YAML parsing supports nested keys', () => {
  const parsed = parseSimpleYaml('settings:\n  bungeecord: true\n  timeout: 30\n');
  assert.equal(parsed.values['settings.bungeecord'], true);
  assert.equal(parsed.values['settings.timeout'], 30);
});

test('insecure fixture exposes actionable security findings', async () => {
  const report = await auditDirectory(new URL('insecure', root));
  assert.equal(report.summary.critical, 1);
  assert.ok(report.findings.some((item) => item.id === 'SEC-004'));
  assert.ok(report.findings.some((item) => item.id === 'SEC-005'));
  assert.match(renderMarkdown(report), /read-only offline audit/);
});

test('balanced fixture avoids critical and high findings', async () => {
  const report = await auditDirectory(new URL('balanced', root));
  assert.equal(report.summary.critical, 0);
  assert.equal(report.summary.high, 0);
  assert.equal(report.files.includes('server.properties'), true);
});

test('rules are deterministic and missing authentication fails closed', () => {
  const findings = auditValues({ 'server-port': '0', 'white-list': 'false' });
  assert.equal(findings[0].id, 'SEC-001');
  assert.equal(findings.find((item) => item.id === 'CFG-001').severity, 'high');
});
