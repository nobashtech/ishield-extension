// iShield clean source module.
// Purpose: readable reviewed source; security boundaries and cross-browser parity are preserved.
// This documentation-only header does not change runtime behavior.

'use strict';

const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const UTF8_FATAL = new TextDecoder('utf-8', { fatal: true });

function syntax(message) {
  const error = new SyntaxError(message);
  error.code = 'ERR_STRICT_JSON';
  return error;
}

function assertNoUnpairedSurrogates(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw syntax('unpaired high surrogate in JSON string');
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw syntax('unpaired low surrogate in JSON string');
    }
  }
}

export function decodeUtf8Strict(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  try { return UTF8_FATAL.decode(view); } catch { throw syntax('invalid UTF-8 JSON body'); }
}

export function isJsonContentType(value) {
  if (Array.isArray(value)) return false;
  const type = String(value ?? '').trim().toLowerCase();
  return /^application\/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8")\s*)?$/u.test(type);
}

export function strictJsonParse(text, {
  maxDepth = 64,
  maxKeys = 100_000,
  maxNodes = 250_000,
  rejectDangerousKeys = true,
} = {}) {
  if (typeof text !== 'string') throw new TypeError('strict JSON input must be a string');
  if (!Number.isSafeInteger(maxDepth) || maxDepth < 1 || maxDepth > 256) throw new TypeError('invalid JSON depth cap');
  if (!Number.isSafeInteger(maxKeys) || maxKeys < 1) throw new TypeError('invalid JSON key cap');
  if (!Number.isSafeInteger(maxNodes) || maxNodes < 1) throw new TypeError('invalid JSON node cap');

  let i = 0;
  let keys = 0;
  let nodes = 0;

  function bumpNode() {
    nodes += 1;
    if (nodes > maxNodes) throw new RangeError('JSON node cap exceeded');
  }

  function skipWs() {
    while (i < text.length && /[\u0020\u0009\u000a\u000d]/u.test(text[i])) i += 1;
  }

  function parseStringToken() {
    if (text[i] !== '"') throw syntax('expected JSON string');
    const start = i;
    i += 1;
    while (i < text.length) {
      const ch = text[i];
      if (ch === '"') {
        i += 1;
        const token = text.slice(start, i);
        let decoded;
        try { decoded = JSON.parse(token); } catch { throw syntax('invalid JSON string'); }
        assertNoUnpairedSurrogates(decoded);
        return decoded;
      }
      const code = text.charCodeAt(i);
      if (code <= 0x1f) throw syntax('control character in JSON string');
      if (ch === '\\') {
        i += 1;
        if (i >= text.length) throw syntax('unterminated JSON escape');
        const esc = text[i];
        if (esc === 'u') {
          const hex = text.slice(i + 1, i + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(hex)) throw syntax('invalid JSON unicode escape');
          i += 5;
          continue;
        }
        if (!/["\\/bfnrt]/u.test(esc)) throw syntax('invalid JSON escape');
      }
      i += 1;
    }
    throw syntax('unterminated JSON string');
  }

  function parseNumberToken() {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(text.slice(i));
    if (!match) throw syntax('invalid JSON number');
    i += match[0].length;
  }

  function parseLiteral(literal) {
    if (text.slice(i, i + literal.length) !== literal) throw syntax('invalid JSON literal');
    i += literal.length;
  }

  function parseArray(depth) {
    if (depth > maxDepth) throw new RangeError('JSON depth cap exceeded');
    i += 1;
    skipWs();
    if (text[i] === ']') { i += 1; return; }
    while (true) {
      parseValue(depth + 1);
      skipWs();
      if (text[i] === ']') { i += 1; return; }
      if (text[i] !== ',') throw syntax('expected comma in JSON array');
      i += 1;
      skipWs();
    }
  }

  function parseObject(depth) {
    if (depth > maxDepth) throw new RangeError('JSON depth cap exceeded');
    i += 1;
    skipWs();
    const seen = new Set();
    if (text[i] === '}') { i += 1; return; }
    while (true) {
      const key = parseStringToken();
      keys += 1;
      if (keys > maxKeys) throw new RangeError('JSON key cap exceeded');
      if (seen.has(key)) throw syntax(`duplicate JSON key: ${key.slice(0, 64)}`);
      if (rejectDangerousKeys && DANGEROUS_KEYS.has(key)) throw syntax('dangerous JSON key rejected');
      seen.add(key);
      skipWs();
      if (text[i] !== ':') throw syntax('expected colon in JSON object');
      i += 1;
      skipWs();
      parseValue(depth + 1);
      skipWs();
      if (text[i] === '}') { i += 1; return; }
      if (text[i] !== ',') throw syntax('expected comma in JSON object');
      i += 1;
      skipWs();
    }
  }

  function parseValue(depth) {
    if (depth > maxDepth) throw new RangeError('JSON depth cap exceeded');
    bumpNode();
    skipWs();
    const ch = text[i];
    if (ch === '{') return parseObject(depth);
    if (ch === '[') return parseArray(depth);
    if (ch === '"') { parseStringToken(); return; }
    if (ch === '-' || (ch >= '0' && ch <= '9')) { parseNumberToken(); return; }
    if (ch === 't') return parseLiteral('true');
    if (ch === 'f') return parseLiteral('false');
    if (ch === 'n') return parseLiteral('null');
    throw syntax('invalid JSON value');
  }

  skipWs();
  if (i >= text.length) throw syntax('empty JSON input');
  parseValue(1);
  skipWs();
  if (i !== text.length) throw syntax('trailing data after JSON value');

  let result;
  try { result = JSON.parse(text); } catch { throw syntax('invalid JSON'); }
  return result;
}
