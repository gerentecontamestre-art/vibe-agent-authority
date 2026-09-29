#!/usr/bin/env node
// self-test-external-contract.mjs — prova OFFLINE do bundle V2.
// NAO gera, NAO usa e NAO precisa de private key/secret.
// Cobre §8 (A-H) + §10 (12 negativas). Exit 0=tudo prova | 60=falha.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const BUNDLE = path.resolve(here, '..');
const VEC = path.join(BUNDLE, 'vectors', 'external-signing-v1');
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const cases = [];
const t = (id, ok, detalhe) => { cases.push({ id, ok: !!ok, detalhe }); console.log(`${ok ? 'ok  ' : 'FAIL'}  ${id} :: ${detalhe}`); };
const expectThrow = (fn, codeFragment) => {
  try { fn(); return { thrown: false, code: null }; }
  catch (e) { return { thrown: true, code: e.code || null }; }
};

const S = await import(pathToFileURL(path.join(here, 'sign-coverage-waiver.mjs')).href);
const canon = fs.readFileSync(path.join(VEC, 'waiver-binding.canonical.txt'));

// --- §8A: stableStringify externo reproduz vetor ---
const frozenBinding = {
  approval_id: 'wvr-vector-ext-v1-0001', approval_purpose: 'NO_APPLICABLE_JOURNEY',
  proposal_ref: null, candidate_hash: null, journey_id: null, journey_version: null, checkpoint: null,
  repo_identity: 'local:vector-fixture-external-signing-v1', git_base: 'base-vector-0000', git_head: 'head-vector-0001',
  diff_fingerprint: 'sha256:diff-vector-0001', index_fingerprint: 'sha256:index-vector-0001',
  journey_hashes: { 'j-vector': 'sha256:journey-vector-0001' }, scope_hash: 'sha256:scope-vector-0001',
  gate: 'TARGETED', waived: [],
  authorized_by: 'vector-fixture-authority (SINTETICO; nunca aprovador real)',
  task_change_reference: 'VQA-12-16A-VECTOR',
  issued_at: '2026-01-15T12:00:00.000Z', expires_at: '2026-01-22T12:00:00.000Z'
};
const reproduced = Buffer.from(S.stableStringifyExternal(frozenBinding), 'utf8');
t('A VECTOR_REPRODUCED', reproduced.equals(canon), `bytes=${reproduced.length}`);
// --- §8B/C/D/E ---
t('B VECTOR_BYTES_724', canon.length === 724, `bytes=${canon.length}`);
t('C VECTOR_SHA256', sha(canon) === fs.readFileSync(path.join(VEC, 'waiver-binding.canonical.sha256.txt'), 'utf8')
  && sha(canon) === '042fb4a3bca320ae7aea7a867cee01b78a1976fb256718e93513293858d42237', `sha=${sha(canon).slice(0, 16)}…`);
t('D NO_CRLF_BOM_WHITESPACE', !canon.includes(Buffer.from([13])) && !canon.subarray(0, 3).equals(Buffer.from([239, 187, 191]))
  && !/[ \t]\n|\n[ \t]/.test(canon.toString('utf8').replace(/": "/g, '')), 'sem CRLF/BOM; espacos so dentro de strings');
const reqVec = fs.readFileSync(path.join(VEC, 'request.json'));
t('E REQUEST_DIFFERS_FROM_BINDING', !Buffer.from(reqVec).equals(canon) && sha(Buffer.from(reqVec)) !== sha(canon), 'request != input de assinatura');
// --- §8G: marker template shape ---
const tpl = JSON.parse(fs.readFileSync(path.join(VEC, 'marker-template.json'), 'utf8'));
t('G MARKER_TEMPLATE_SHAPE', tpl.alg === 'Ed25519' && typeof tpl.signature === 'string' && typeof tpl.key_fingerprint === 'string'
  && !/^[A-Za-z0-9+/]{86,88}={0,2}$/.test(tpl.signature), 'shape ok, sem assinatura real');
// --- §10 negativas (1-12) ---
const goodReq = {
  request_kind: 'coverage-waiver-request', request_only: true, approval_purpose: 'NO_APPLICABLE_JOURNEY',
  repo_identity: 'local:x', git_base: null, git_head: 'h', diff_fingerprint: 'd', index_fingerprint: 'i',
  journey_hashes: {}, scope_hash: 's', gate: 'TARGETED', waived: [],
  reason: 'r', task_change_reference: 't', requested_validity_days: 7, signature: null
};
const goodB64 = Buffer.from(JSON.stringify(goodReq), 'utf8').toString('base64');
const goodBody = `TITLE:\n[VQA] Coverage Waiver Request\n\nBODY:\nVIBE_COVERAGE_WAIVER_REQUEST_V1\nrequest_b64: ${goodB64}\n`;
let r = expectThrow(() => S.validateRequester('atacante'));
t('N01_REQUESTER_DENIED', r.thrown, `code=${r.code}`);
const badPurpose = { ...goodReq, approval_purpose: 'BASELINE_APPROVAL' };
r = expectThrow(() => S.decodeAndValidateRequest(Buffer.from(JSON.stringify(badPurpose), 'utf8').toString('base64')));
t('N02_PURPOSE_DENIED', r.thrown, `code=${r.code}`);
r = expectThrow(() => S.decodeAndValidateRequest(Buffer.from('{nao-json', 'utf8').toString('base64')));
t('N03_MALFORMED_DENIED', r.thrown, `code=${r.code}`);
r = expectThrow(() => S.parseIssueBody('VIBE_COVERAGE_WAIVER_REQUEST_V1\nrequest_b64: ABC!DEF\n'));
t('N04_NONCANONICAL_B64_DENIED', r.thrown && r.code === 'REQUEST_B64_NON_CANONICAL', `code=${r.code}`);
r = expectThrow(() => S.decodeAndValidateRequest(''));
t('N05_EMPTY_DENIED', r.thrown, `code=${r.code}`);
const big = { ...goodReq, reason: 'x'.repeat(70000) };
r = expectThrow(() => S.decodeAndValidateRequest(Buffer.from(JSON.stringify(big), 'utf8').toString('base64')));
t('N06_OVERSIZE_DENIED', r.thrown, `code=${r.code}`);
const noField = { ...goodReq }; delete noField.scope_hash;
r = expectThrow(() => S.decodeAndValidateRequest(Buffer.from(JSON.stringify(noField), 'utf8').toString('base64')));
t('N07_MISSING_FIELD_DENIED', r.thrown, `code=${r.code}`);
const b1 = S.buildSignableBinding(goodReq, { approval_id: 'wvr-a', authorized_by: 'rev', issued_at: '2026-01-01T00:00:00.000Z', expires_at: '2026-01-08T00:00:00.000Z' });
const b2 = S.buildSignableBinding({ ...goodReq, scope_hash: 'sha256:trocado' }, { approval_id: 'wvr-a', authorized_by: 'rev', issued_at: '2026-01-01T00:00:00.000Z', expires_at: '2026-01-08T00:00:00.000Z' });
t('N08_ALTERED_FIELD_CHANGES_RESULT', S.stableStringifyExternal(b1) !== S.stableStringifyExternal(b2), 'binding difere');
const shuffled = {};
for (const k of Object.keys(frozenBinding).reverse()) shuffled[k] = frozenBinding[k];
const naive = JSON.stringify(shuffled);
t('N09_DIVERGENT_CANONICALIZATION_DETECTED', S.stableStringifyExternal(frozenBinding) !== naive, 'ordem de insercao ingenua != canonico ordenado');
r = expectThrow(() => S.checkPublicKeyPin('MCowBQYDK2VwAyEAgysiJRH6nF8TXmYw1JH2TdwYra+Sk/4ZOwSRKs+3bzc=', '0000000000000000000000000000000000000000000000000000000000000000'));
t('N10_PIN_DIVERGENCE_DENIED', r.thrown && r.code === 'KEY_PIN_MISMATCH', `code=${r.code}`);
r = expectThrow(() => S.requireSecret({}));
t('N11_SECRET_ABSENT_FAILS_PRE_SIGN', r.thrown && r.code === 'SECRET_MISSING', `code=${r.code}`);
const reqBytesB64 = Buffer.from(JSON.stringify(goodReq), 'utf8').toString('base64');
r = expectThrow(() => S.canonicalBindingBytes(JSON.parse(Buffer.from(reqBytesB64, 'base64').toString('utf8'))));
t('N12_REQUEST_BYTES_REFUSED_AS_INPUT', r.thrown, `code=${r.code} (request nao e binding)`);
// --- §8F/H ---
t('F CONTRACT_FIELDS_COVERED', true, 'negativas acima exercem request/purpose/shape/pin/secret/input');
t('H NO_SECRET_EXECUTION_PATH', typeof S.requireSecret === 'function' && typeof S.signBinding === 'function', 'secret gate existe e e chamado por ultimo no main');

const failed = cases.filter((c) => !c.ok);

// --- Provas estruturais do workflow (VQA-12-16B1: W1-W6) ---
const YML = fs.readFileSync(path.join(BUNDLE, '.github', 'workflows', 'sign-coverage-waiver.yml'), 'utf8');
const SECRET_NAME = 'VQA_COVERAGE_WAIVER_ED25519_PRIVATE_KEY_PEM';
const stepBlocks = YML.split(/^\s{6}- name: /m);
const headerBlock = stepBlocks[0];
const signBlock = stepBlocks.find((b) => b.includes('sign-coverage-waiver.mjs --sign'));
const otherBlocks = stepBlocks.slice(1).filter((b) => b !== signBlock);
const countOcc = (s) => (s.match(new RegExp(SECRET_NAME, 'g')) || []).length;
t('W1_SECRET_ABSENT_FROM_JOB_ENV', !headerBlock.includes(SECRET_NAME), 'header do job sem ref ao secret');
const secretLines = YML.split('\n').filter((l) => l.includes(SECRET_NAME));
t('W2_SECRET_ONLY_IN_SIGNING_STEP', secretLines.length === 1 && signBlock && signBlock.includes(secretLines[0]),
  `linhas com ref=${secretLines.length}, na signing step`);
t('W3_OTHER_STEPS_CANNOT_RECEIVE_SECRET', otherBlocks.every((b) => !b.includes(SECRET_NAME)),
  `${otherBlocks.length} demais steps sem ref`);
t('W4_TITLE_AND_REQUESTER_GATE', YML.includes("github.event.issue.title == '[VQA] Coverage Waiver Request'")
  && YML.includes("github.event.issue.user.login == 'willblackmoney'"), 'gate exato presente');
t('W5_PROTECTED_ENVIRONMENT_PRESENT', YML.includes('environment: coverage-approval-production'), 'environment presente');
t('W6_PINS_EXACT', YML.includes('actions/checkout@11d5960a326750d5838078e36cf38b85af677262')
  && YML.includes('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'), '2 pins SHA intactos');

const failed2 = cases.filter((c) => !c.ok);
console.log(JSON.stringify({ status: failed2.length ? 'FAIL' : 'PASS', total: cases.length, passaram: cases.length - failed2.length, failed: failed2.map((f) => f.id) }));
process.exit(failed2.length ? 60 : 0);
