import { config } from '../config/env.mjs';
import { httpError } from '../utils/validation.mjs';

export function sendJson(response, status, payload) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': config.corsOrigin,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
  });
  response.end(JSON.stringify(payload));
}

export function sendError(response, status, message) {
  sendJson(response, status, { error: { message } });
}

export async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > config.maxBodyBytes) throw httpError(413, 'Request body is too large');
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw httpError(400, 'Request body must be valid JSON'); }
}

export async function readEmailInput(request) {
  const contentType = request.headers['content-type'] || '';
  if (!contentType.startsWith('multipart/form-data')) return readJson(request);
  const boundary = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i)?.[1] || contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i)?.[2];
  if (!boundary) throw httpError(400, 'Multipart boundary is required');
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > config.maxBodyBytes) throw httpError(413, 'Request body is too large');
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  const fields = {};
  for (const part of raw.split(`--${boundary}`).slice(1)) {
    if (!part || part.startsWith('--')) continue;
    const separator = part.search(/\r?\n\r?\n/);
    if (separator < 0) continue;
    const partHeaders = part.slice(0, separator);
    const content = part.slice(separator).replace(/^\r?\n\r?\n/, '').replace(/\r?\n$/, '');
    const name = partHeaders.match(/name="([^"]+)"/i)?.[1];
    if (name) fields[name] = content;
  }
  if (!fields.file?.trim()) throw httpError(400, 'Email file is required');
  return { rawEmail: fields.file, analysisId: fields.analysisId, inputHash: fields.inputHash, inputMethod: 'upload', fileName: fields.fileName || 'uploaded.eml' };
}
