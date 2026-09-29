#!/usr/bin/env node
// sign-coverage-waiver.mjs — SIGNER V2 (executa SOMENTE no GitHub Environment
// protegido, após human review). Derivado mecanicamente de
// EXTERNAL-SIGNING-CONTRACT-V1. Contrato: assina utf8(stableStringify(
// waiverBinding)) — 20 campos. NUNCA assina bytes do request.
// Secret SOMENTE via env (nome abaixo); valor jamais impresso/persistido.
// Node >= 20, zero dependencias. Sem chamadas de rede.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

// ---- Trust config publica (pin) ----
export const PINNED = {
  providerType: 'ed25519-detached',
  purpose: 'NO_APPLICABLE_JOURNEY',
  publicKeyDerB64: 'MCowBQYDK2VwAyEAgysiJRH6nF8TXmYw1JH2TdwYra+Sk/4ZOwSRKs+3bzc=',
  publicKeyFingerprint: '272645c8fbdc47730f65dc3c10623217a059660c26cee7b5e99525ad8cecd859',
  allowedRequester: 'willblackmoney',
  // Nome do secret APENAS. O valor nunca existe neste arquivo.
  secretEnvName: 'VQA_COVERAGE_WAIVER_ED25519_PRIVATE_KEY_PEM',
  maxRequestBytes: 65536, // guarda de transporte do bundle (nao e semantica do verifier)
  validityDaysCap: 7
};
const BINDING_KEYS = ['approval_id', 'approval_purpose', 'proposal_ref', 'candidate_hash',
  'journey_id', 'journey_version', 'checkpoint', 'repo_identity', 'git_base', 'git_head',
  'diff_fingerprint', 'index_fingerprint', 'journey_hashes', 'scope_hash', 'gate',
  'waived', 'authorized_by', 'task_change_reference', 'issued_at', 'expires_at'];
const NULLABLE = new Set(['proposal_ref', 'candidate_hash', 'journey_id', 'journey_version', 'checkpoint', 'git_base']);

export function fail(code, message) {
  const err = new Error(message);
  err.code = code;
  throw err;
}

// Canonicalizacao logica identica ao stableStringify canonico:
// chaves ordenadas (UTF-16), recursiva, sem whitespace, primitivas via JSON.
export function stableStringifyExternal(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringifyExternal).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringifyExternal(value[k])}`).join(',')}}`;
}

// 1. Request transportado via Issue.
export function parseIssueBody(body) {
  const text = String(body || '');
  if (!text.includes('VIBE_COVERAGE_WAIVER_REQUEST_V1')) fail('REQUEST_MALFORMED', 'Marcador do request ausente no corpo da Issue.');
  const m = text.match(/request_b64:\s*([A-Za-z0-9+/=\s]+)/);
  if (!m) fail('REQUEST_MALFORMED', 'Campo request_b64 ausente.');
  const compact = m[1].replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(compact) || compact.length % 4 !== 0 || compact.length === 0) {
    fail('REQUEST_B64_NON_CANONICAL', 'Base64 fora do formato canonico estrito.');
  }
  return compact;
}

// 2. Identidade do requester (policy externa: só willblackmoney).
export function validateRequester(login) {
  if (login !== PINNED.allowedRequester) fail('REQUESTER_DENIED', `Requester nao autorizado: ${login}.`);
  return true;
}

// 3. Decodifica + valida shape do request ANTES de qualquer uso do secret.
export function decodeAndValidateRequest(requestB64) {
  const bytes = Buffer.from(requestB64, 'base64');
  if (bytes.length === 0) fail('REQUEST_EMPTY', 'Request vazio.');
  if (bytes.length > PINNED.maxRequestBytes) fail('REQUEST_TOO_LARGE', `Request acima do limite de transporte (${PINNED.maxRequestBytes}B).`);
  let req;
  try { req = JSON.parse(bytes.toString('utf8')); }
  catch { fail('REQUEST_MALFORMED', 'Request nao e JSON valido.'); }
  if (req.request_kind !== 'coverage-waiver-request' || req.request_only !== true) {
    fail('REQUEST_MALFORMED', 'Envelope de request invalido.');
  }
  if (req.approval_purpose !== PINNED.purpose) fail('PURPOSE_DENIED', `Purpose nao autorizado: ${req.approval_purpose}.`);
  for (const k of ['repo_identity', 'git_head', 'diff_fingerprint', 'index_fingerprint', 'journey_hashes', 'scope_hash', 'gate', 'reason', 'task_change_reference']) {
    if (req[k] === undefined || req[k] === null || req[k] === '') fail('REQUEST_FIELD_MISSING', `Campo obrigatorio ausente: ${k}.`);
  }
  return { bytes, req };
}

// 4-6. Binding com EXATAMENTE os 20 campos + campos de autoridade.
export function buildSignableBinding(req, authority) {
  for (const k of ['approval_id', 'authorized_by', 'issued_at', 'expires_at']) {
    if (!authority || authority[k] === undefined || authority[k] === null || authority[k] === '') {
      fail('AUTHORITY_FIELD_MISSING', `Campo de autoridade ausente: ${k}.`);
    }
  }
  const binding = {
    approval_id: authority.approval_id, approval_purpose: PINNED.purpose,
    proposal_ref: req.proposal_ref ?? null, candidate_hash: req.candidate_hash ?? null,
    journey_id: req.journey_id ?? null, journey_version: req.journey_version ?? null,
    checkpoint: req.checkpoint ?? null,
    repo_identity: req.repo_identity, git_base: req.git_base ?? null, git_head: req.git_head,
    diff_fingerprint: req.diff_fingerprint, index_fingerprint: req.index_fingerprint,
    journey_hashes: req.journey_hashes, scope_hash: req.scope_hash, gate: req.gate,
    waived: req.waived || [],
    authorized_by: authority.authorized_by, task_change_reference: req.task_change_reference,
    issued_at: authority.issued_at, expires_at: authority.expires_at
  };
  assertSignableBinding(binding);
  return binding;
}

// Barreira: SOMENTE objeto com os 20 campos chega a assinatura.
// Bytes de request (ou qualquer outro shape) sao recusados aqui,
// ANTES de qualquer carregamento de secret.
export function assertSignableBinding(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) fail('SIGNATURE_INPUT_DENIED', 'Input de assinatura deve ser objeto binding.');
  const keys = Object.keys(obj).sort();
  const want = [...BINDING_KEYS].sort();
  if (JSON.stringify(keys) !== JSON.stringify(want)) {
    fail('SIGNATURE_INPUT_DENIED', 'Input nao e waiverBinding de 20 campos (bytes de request recusados).');
  }
  for (const k of BINDING_KEYS) {
    if ((obj[k] === undefined || obj[k] === null) && !NULLABLE.has(k)) {
      fail('SIGNATURE_INPUT_DENIED', `Campo assinavel ausente: ${k}.`);
    }
  }
  if (obj.approval_purpose !== PINNED.purpose) fail('PURPOSE_DENIED', 'Purpose do binding nao autorizado.');
  return true;
}

export function canonicalBindingBytes(binding) {
  assertSignableBinding(binding);
  return Buffer.from(stableStringifyExternal(binding), 'utf8');
}

export function deriveApprovalId(requestSha256, issueNumber, runId) {
  return `wvr-ext-${crypto.createHash('sha256').update(`${requestSha256}|${issueNumber}|${runId}`).digest('hex').slice(0, 16)}`;
}

// 9. Secret carregado POR ULTIMO (apos todas as validacoes).
// O VALOR jamais e impresso, logado ou retornado em erro.
export function requireSecret(env) {
  const v = env ? env[PINNED.secretEnvName] : undefined;
  if (typeof v !== 'string' || v.length < 32) fail('SECRET_MISSING', `Secret ${PINNED.secretEnvName} ausente/invalido no environment.`);
  return v;
}

// 10. Deriva publica e confere pins (sem expor o secret).
// checkPublicKeyPin e puro (sem secret): compara DER + fingerprint.
export function checkPublicKeyPin(derB64, expectedFp) {
  let der;
  try { der = Buffer.from(String(derB64 || ''), 'base64'); }
  catch { fail('KEY_PIN_MISMATCH', 'Public key fora do formato esperado.'); }
  const fp = crypto.createHash('sha256').update(der).digest('hex');
  if (derB64 !== PINNED.publicKeyDerB64 || fp !== expectedFp || fp !== PINNED.publicKeyFingerprint) {
    fail('KEY_PIN_MISMATCH', 'Public key/fingerprint diverge do pinado.');
  }
  return { derB64, fp };
}
export function checkKeyPins(privateKeyPem) {
  let key;
  try { key = crypto.createPrivateKey(privateKeyPem); }
  catch { fail('SECRET_INVALID', 'Secret nao e chave privada valida.'); }
  if (key.asymmetricKeyType !== 'ed25519') fail('SECRET_INVALID', 'Secret nao e chave Ed25519.');
  const pub = crypto.createPublicKey(key);
  const der = pub.export({ format: 'der', type: 'spki' });
  const checked = checkPublicKeyPin(der.toString('base64'), PINNED.publicKeyFingerprint);
  return { privateKey: key, publicKey: pub, derB64: checked.derB64, fp: checked.fp };
}

// 11-13. Assina bytes canonicos; monta marker + artifact (envelope de transporte).
export function signBinding(binding, privateKey) {
  const bytes = canonicalBindingBytes(binding);
  const sig = crypto.sign(null, bytes, privateKey);
  if (sig.length !== 64) fail('SIGN_FAILED', 'Assinatura fora do tamanho esperado.');
  return { bytes, signatureB64: sig.toString('base64') };
}

export function buildArtifact({ binding, signatureB64, requestSha256, meta }) {
  const bindingBytes = canonicalBindingBytes(binding);
  return {
    schema_version: 1,
    artifact_type: 'vibe.coverage-waiver.detached-signature',
    signature_input: 'stableStringify(waiverBinding)',
    contract: 'EXTERNAL-SIGNING-CONTRACT-V1',
    provider_type: PINNED.providerType,
    approval_purpose: PINNED.purpose,
    request_sha256: requestSha256,
    binding_sha256: crypto.createHash('sha256').update(bindingBytes).digest('hex'),
    signature_algorithm: 'Ed25519',
    signature_b64: signatureB64,
    public_key_der_b64: PINNED.publicKeyDerB64,
    public_key_fingerprint_sha256: PINNED.publicKeyFingerprint,
    waiver: { ...binding, provider_id: meta.providerId, provider_marker: { alg: 'Ed25519', signature: signatureB64, key_fingerprint: PINNED.publicKeyFingerprint } },
    authority: {
      repository: meta.repository, environment: meta.environment,
      requester: meta.requester, reviewer: meta.reviewer,
      issue_number: meta.issueNumber, run_id: String(meta.runId), workflow_sha: meta.workflowSha
    }
  };
}

// ---- main (somente com --sign; import seguro para self-test) ----
function argValue(name) {
  const i = process.argv.indexOf(name);
  return i !== -1 && i + 1 < process.argv.length ? process.argv[i + 1] : null;
}
const isCli = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isCli && process.argv.includes('--sign')) {
  try {
    const major = Number(process.versions.node.split('.')[0]);
    if (!(major >= 20)) fail('RUNTIME_UNSUPPORTED', `Node >= 20 exigido (atual: ${process.versions.node}).`);
    const requester = argValue('--requester');
    validateRequester(requester);
    const body = fs.readFileSync(path.resolve(argValue('--issue-body-file')), 'utf8');
    const requestB64 = parseIssueBody(body);
    const { bytes: reqBytes, req } = decodeAndValidateRequest(requestB64);
    const requestSha256 = crypto.createHash('sha256').update(reqBytes).digest('hex');
    const issueNumber = Number(argValue('--issue-number'));
    const runId = String(argValue('--run-id') || '');
    const reviewer = argValue('--reviewer');
    if (!reviewer || reviewer === requester) fail('REVIEWER_INVALID', 'Reviewer humano distinto do requester e obrigatorio.');
    const validityDays = Math.min(Number.isInteger(req.requested_validity_days) ? req.requested_validity_days : PINNED.validityDaysCap, PINNED.validityDaysCap);
    const issuedAt = new Date().toISOString();
    const binding = buildSignableBinding(req, {
      approval_id: deriveApprovalId(requestSha256, issueNumber, runId),
      authorized_by: reviewer,
      issued_at: issuedAt,
      expires_at: new Date(Date.parse(issuedAt) + validityDays * 86400000).toISOString()
    });
    // Secret POR ULTIMO, apos todas as validacoes e vetores.
    const secret = requireSecret(process.env);
    const { privateKey } = checkKeyPins(secret);
    const { signatureB64 } = signBinding(binding, privateKey);
    const artifact = buildArtifact({
      binding, signatureB64, requestSha256,
      meta: {
        providerId: 'vqa-coverage-waiver-ed25519', repository: 'gerentecontamestre-art/vibe-agent-authority',
        environment: 'coverage-approval-production', requester, reviewer,
        issueNumber, runId, workflowSha: argValue('--workflow-sha') || ''
      }
    });
    const outFile = path.resolve(argValue('--out') || 'coverage-waiver-detached-signature.json');
    fs.writeFileSync(outFile, JSON.stringify(artifact, null, 2));
    // Saida publica apenas: hashes/ids, nunca secret.
    console.log(JSON.stringify({
      status: 'PASS', code: 'SIGNED_V2',
      request_sha256: requestSha256, binding_sha256: artifact.binding_sha256,
      approval_id: binding.approval_id, issued_at: binding.issued_at, expires_at: binding.expires_at,
      key_fingerprint: PINNED.publicKeyFingerprint, out: outFile
    }, null, 2));
    process.exit(0);
  } catch (e) {
    // NUNCA ecoar variaveis/conteudo sensivel: so codigo + mensagem estatica.
    console.log(JSON.stringify({ status: 'FAIL', code: e.code || 'SIGNER_ERROR', message: String(e.message || e).slice(0, 200) }));
    const code = String(e.code || '');
    const exit = code === 'SECRET_MISSING' ? 40 : (code.includes('DENIED') || code === 'PURPOSE_DENIED' ? 30 : 10);
    process.exit(exit);
  }
}
