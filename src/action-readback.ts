import { createHash } from 'node:crypto';

export interface ActionReadback {
  tool: string;
  action: string;
  destination?: string;
  payload_preview: unknown;
  payload_hash: string;
  payload_bytes: number;
  disclosed_fields: string[];
  redacted_fields: string[];
  summary: string;
}

const SECRET_KEY_RE = /(api[_-]?key|authorization|bearer|credential|password|secret|session|token|private[_-]?key)/i;
const DESTINATION_KEYS = [
  'path', 'file_path', 'filePath', 'url', 'uri', 'endpoint', 'host', 'hostname',
  'repo', 'repository', 'branch', 'channel', 'to', 'recipient', 'symbol',
  'account', 'bucket', 'database', 'table', 'service',
];

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`).join(',')}}`;
}

// The readback is signed into the receipt, so it must always be a form the
// receipt's JCS profile accepts, whatever the agent sent: valid Unicode,
// printable-ASCII keys, finite numbers and no undefined members. Otherwise an
// agent could choose which of its calls go unsigned. The payload hash still
// covers the input exactly as sent.

/** Lone surrogates (invalid Unicode) become U+FFFD. */
function wellFormed(text: string): string {
  return text.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '\uFFFD');
}

/** A key outside printable ASCII is written with \uXXXX escapes; `__proto__` is escaped so it stays an ordinary member. */
function previewKey(key: string): string {
  const escaped = key.replace(/[^\x20-\x7E]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
  return escaped === '__proto__' ? '\\u005f_proto__' : escaped;
}

function redact(value: unknown, path: string[] = [], redacted: string[] = [], disclosed: string[] = [], depth = 0): unknown {
  if (depth > 4) return '[truncated-depth]';
  if (value === null || value === undefined) return value;
  if (typeof value !== 'object') {
    if (path.length > 0) disclosed.push(path.join('.'));
    if (typeof value === 'string') return wellFormed(value.length > 240 ? `${value.slice(0, 240)}...` : value);
    if (typeof value === 'number' && !Number.isFinite(value)) return null; // as JSON.stringify forwards it
    return value;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item, idx) => redact(item, [...path, String(idx)], redacted, disclosed, depth + 1));
  }
  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    // An escaped key never replaces another member, so the preview hides none.
    let shown = previewKey(key);
    while (Object.prototype.hasOwnProperty.call(out, shown)) shown += '~';
    const childPath = [...path, shown];
    if (SECRET_KEY_RE.test(key)) {
      redacted.push(childPath.join('.'));
      out[shown] = '[redacted]';
      continue;
    }
    out[shown] = redact(child, childPath, redacted, disclosed, depth + 1);
  }
  return out;
}

function firstStringValue(input: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = input[key];
    if (typeof value === 'string' && value.trim()) return wellFormed(value.trim());
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  }
  return undefined;
}

function actionFor(tool: string, input: Record<string, unknown>): string {
  const explicit = firstStringValue(input, ['action', 'operation', 'method', 'verb', 'command']);
  if (explicit) return explicit.length > 90 ? wellFormed(`${explicit.slice(0, 90)}...`) : explicit;
  return tool;
}

export function buildActionReadback(tool: string, input: unknown): ActionReadback {
  const normalized = input && typeof input === 'object' && !Array.isArray(input)
    ? input as Record<string, unknown>
    : { value: input };
  const canonical = stableStringify(normalized);
  const redactedFields: string[] = [];
  const disclosedFields: string[] = [];
  const payloadPreview = redact(normalized, [], redactedFields, disclosedFields);
  const shownTool = typeof tool === 'string' ? wellFormed(tool) : tool;
  const action = actionFor(shownTool, normalized);
  const destination = firstStringValue(normalized, DESTINATION_KEYS);
  const summary = destination
    ? `${shownTool} -> ${destination}`
    : `${shownTool} request`;

  return {
    tool: shownTool,
    action,
    // Absent rather than undefined: a receipt cannot carry an undefined member.
    ...(destination !== undefined ? { destination } : {}),
    payload_preview: payloadPreview,
    payload_hash: createHash('sha256').update(canonical).digest('hex'),
    payload_bytes: Buffer.byteLength(canonical, 'utf-8'),
    disclosed_fields: [...new Set(disclosedFields)].slice(0, 80),
    redacted_fields: [...new Set(redactedFields)].slice(0, 80),
    summary,
  };
}
