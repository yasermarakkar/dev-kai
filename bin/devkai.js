#!/usr/bin/env node
const MIN_NODE_MAJOR = 21;
const major = Number(process.versions.node.split('.')[0]);
if (major < MIN_NODE_MAJOR) {
  process.stderr.write(`devkai: Node ${MIN_NODE_MAJOR}+ required (found ${process.versions.node}).\n`);
  process.exit(2);
}

const { main } = await import('../src/cli.js');

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    process.stderr.write(`devkai: ${err.message}\n`);
    process.exitCode = 2;
  },
);
