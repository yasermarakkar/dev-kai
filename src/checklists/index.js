import security from './security.js';
import logging from './logging.js';

/**
 * Registry of all checklists. Each one produces its own file in the output folder.
 * Add a new category by creating `<id>.js` with defineChecklist() and listing it here.
 */
export const checklists = [security, logging];
