/**
 * @scopeblind/protect-mcp: resuming a receipt log's chain
 *
 * Every receipt carries the s5.7 link to the line before it, so on restart the
 * gate continues the chain from the receipt log's last line.
 */

import { existsSync, readFileSync, renameSync } from 'node:fs';

/**
 * The link to continue the chain from, or null to start a new chain.
 *
 * A missing or empty log starts a new chain. A log whose last line cannot be
 * read as a receipt (it is not JSON, or cannot be hashed) is not silently
 * restarted, since that would hide a break in the record. An enforcing gate
 * refuses to start and names the file. An observing gate moves the file aside
 * to `<name>.corrupt-<UTC timestamp>` (it is never deleted), warns, and starts
 * the new chain in a fresh file.
 */
export function resumeReceiptLog(
  path: string,
  options: { enforce: boolean; link: (receipt: unknown) => string; warn: (message: string) => void },
): string | null {
  let lines: string[];
  try {
    lines = readFileSync(path, 'utf-8').split('\n').filter((line) => line.trim());
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    return cannotContinue(path, 'cannot be read', options);
  }
  if (lines.length === 0) return null;
  let last: unknown;
  try {
    last = JSON.parse(lines[lines.length - 1]);
  } catch {
    return cannotContinue(path, 'ends in a line that is not JSON', options);
  }
  try {
    return options.link(last);
  } catch {
    return cannotContinue(path, 'ends in a line that cannot be hashed as a receipt', options);
  }
}

function cannotContinue(path: string, problem: string, options: { enforce: boolean; warn: (message: string) => void }): null {
  if (options.enforce) {
    throw new Error(
      `enforce mode refused to start: the receipt log ${path} ${problem}, so its chain cannot be continued. ` +
      'Inspect the file, and move it aside to start a new chain.',
    );
  }
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  let aside = `${path}.corrupt-${stamp}`;
  for (let n = 2; existsSync(aside); n++) aside = `${path}.corrupt-${stamp}-${n}`;
  renameSync(path, aside);
  options.warn(`Warning: the receipt log ${path} ${problem}. It was moved to ${aside}, and a new chain starts in a fresh file.`);
  return null;
}
