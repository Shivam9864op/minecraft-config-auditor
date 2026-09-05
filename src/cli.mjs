#!/usr/bin/env node
import { auditDirectory, renderMarkdown } from './audit.mjs';

const directory = process.argv[2];
const formatIndex = process.argv.indexOf('--format');
const format = formatIndex >= 0 ? process.argv[formatIndex + 1] : 'markdown';
if (!directory || !['markdown', 'json'].includes(format)) {
  console.error('Usage: node src/cli.mjs <fixture-directory> [--format markdown|json]');
  process.exitCode = 2;
} else {
  const report = await auditDirectory(directory);
  process.stdout.write(format === 'json' ? JSON.stringify(report, null, 2) + '\n' : renderMarkdown(report));
}
