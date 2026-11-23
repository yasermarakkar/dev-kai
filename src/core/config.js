import fs from 'node:fs';
import path from 'node:path';

export const CONFIG_FILE = 'devkai.config.json';

export const DEFAULT_CONFIG = {
  outDir: 'readiness',
  // Extra paths to skip, on top of node_modules, dist, build, etc.
  ignore: [],
  // Check ids to turn off, e.g. ["SEC-013"]
  disable: [],
  // Override severity per check id, e.g. { "SEC-007": "low" }
  severity: {},
};

export function loadConfig(root, explicitPath) {
  const file = explicitPath ? path.resolve(explicitPath) : path.join(root, CONFIG_FILE);
  if (!fs.existsSync(file)) {
    if (explicitPath) throw new Error(`Config not found: ${file}`);
    return { ...DEFAULT_CONFIG };
  }
  try {
    return { ...DEFAULT_CONFIG, ...JSON.parse(fs.readFileSync(file, 'utf8')) };
  } catch (err) {
    throw new Error(`Invalid JSON in ${file}: ${err.message}`);
  }
}

export function writeDefaultConfig(root) {
  const file = path.join(root, CONFIG_FILE);
  if (fs.existsSync(file)) return { file, created: false };
  fs.writeFileSync(file, `${JSON.stringify(DEFAULT_CONFIG, null, 2)}\n`);
  return { file, created: true };
}
