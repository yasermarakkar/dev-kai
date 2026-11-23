import security from './security.js';
import logging from './logging.js';
import monitoring from './monitoring.js';
import auditing from './auditing.js';
import database from './database.js';
import scalability from './scalability.js';
import reliability from './reliability.js';
import cicd from './cicd.js';

/**
 * Registry of all checklists. Each one produces its own file in the output folder.
 * Add a new category by creating `<id>.js` with defineChecklist() and listing it here.
 */
export const checklists = [security, logging, monitoring, auditing, database, scalability, reliability, cicd];
