'use strict';

const fs = require('fs');
const path = require('path');

const DICT_DIR = path.join(__dirname, '..', 'dict');

function readList(file) {
  try {
    return fs
      .readFileSync(path.join(DICT_DIR, file), 'utf8')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
  } catch (_e) {
    return [];
  }
}

/**
 * Resolve the list of paths to probe for a scan.
 *   - 'default'  : the curated default_targets.txt list.
 *   - 'linux'    : linux_sensitive_path.txt.
 *   - 'windows'  : windows_sensitive_path.txt.
 *   - 'platform' : linux or windows list based on detected platform.
 */
function pathsFor(mode, platform) {
  switch (mode) {
    case 'linux':
      return readList('linux_sensitive_path.txt');
    case 'windows':
      return readList('windows_sensitive_path.txt');
    case 'platform':
      return readList(
        platform === 'windows'
          ? 'windows_sensitive_path.txt'
          : 'linux_sensitive_path.txt'
      );
    case 'default':
    default:
      return readList('default_targets.txt');
  }
}

module.exports = { readList, pathsFor, DICT_DIR };
