import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from "node:crypto";
import fs from "node:fs/promises";

const EXPECTED_PUBLIC_KEY_DER_B64 =
  "MCowBQYDK2VwAyEAgysiJRH6nF8TXmYw1JH2TdwYra+Sk/4ZOwSRKs+3bzc=";

const EXPECTED_FINGERPRINT =
  "272645c8fbdc47730f65dc3c10623217a059660c26cee7b5e99525ad8cecd859";

function fail(message) {
  console.error(`AUTHORITY_SIGNER_DENIED: ${message}`);
  process.exit(1);
}

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) fail(`missing environment variable: ${name}`);
  return value;
}

function extractRequestB64(issueBody) {
  const match = issueBody.match(
    /VIBE_COVERAGE_WAIVER_REQUEST_V1\s*\nrequest_b64:\s*([A-Za-z0-9+/=]+)\s*(?:\n|$)/
  );

  if (!match) {
    fail(
      "issue body must contain VIBE_COVERAGE_WAIVER_REQUEST_V1 followed by request_b64"
    );
  }

  return match[1];
}

function strictBase64Decode(value) {
  const normalized = value.replace(/\s+/g, "");

  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) {
    fail("request_b64 is not valid base64");
  }

  const bytes = Buffer.from(normalized, "base64");

  if (bytes.length === 0) {
    fail("decoded request is empty");
  }

  if (bytes.length > 48 * 1024) {
    fail("decoded request exceeds 48 KiB");
  }

  const roundTrip = bytes.toString("base64");

  if (roundTrip !== normalized) {
    fail("request_b64 is not canonical base64");
  }

  return bytes;
}

const eventPath = requiredEnv("GITHUB_EVENT_PATH");
const privateKeyPem = requiredEnv(
  "VQA_COVERAGE_WAIVER_ED25519_PRIVATE_KEY_PEM"
);

const rawEvent = await fs.readFile(eventPath, "utf8");
const event = JSON.parse(rawEvent);

if (!event.issue || typeof event.issue.body !== "string") {
  fail("workflow event does not contain an issue body");
}

if (event.action !== "opened") {
  fail(`unsupported issue action: ${event.action}`);
}

const requester = event.sender?.login;

if (!requester) {
  fail("requester identity missing");
}

if (requester !== "willblackmoney") {
  fail("requester is not authorized for this authority");
}

const requestB64 = extractRequestB64(event.issue.body);
const requestBytes = strictBase64Decode(requestB64);

/*
 * Parse only for purpose validation.
 * The signature itself is over the EXACT decoded bytes.
 */
let requestObject;

try {
  requestObject = JSON.parse(requestBytes.toString("utf8"));
} catch {
  fail("coverage waiver request is not valid UTF-8 JSON");
}

if (
  requestObject === null ||
  Array.isArray(requestObject) ||
  typeof requestObject !== "object"
) {
  fail("coverage waiver request must be a JSON object");
}

const purpose =
  requestObject.approval_purpose ??
  requestObject.purpose ??
  null;

if (purpose !== "NO_APPLICABLE_JOURNEY") {
  fail(
    `invalid approval purpose: ${String(purpose)}; expected NO_APPLICABLE_JOURNEY`
  );
}

/*
 * Load secret without ever printing it.
 */
let privateKey;

try {
  privateKey = createPrivateKey(privateKeyPem);
} catch {
  fail("environment secret is not a valid private key");
}

/*
 * Derive the public key from the secret and prove that the secret belongs
 * to the public key/fingerprint William provisioned.
 */
const publicKey = createPublicKey(privateKey);
const derivedDer = publicKey.export({
  type: "spki",
  format: "der",
});

const derivedDerB64 = derivedDer.toString("base64");
const derivedFingerprint = sha256(derivedDer);

if (derivedDerB64 !== EXPECTED_PUBLIC_KEY_DER_B64) {
  fail("private key does not match pinned public key");
}

if (derivedFingerprint !== EXPECTED_FINGERPRINT) {
  fail("private key does not match pinned public-key fingerprint");
}

/*
 * Ed25519 signs the exact request bytes.
 */
const signature = sign(null, requestBytes, privateKey);

const artifact = {
  schema_version: 1,
  artifact_type: "vibe.coverage-waiver.detached-signature",
  provider_type: "ed25519-detached",

  approval_purpose: "NO_APPLICABLE_JOURNEY",

  request_sha256: sha256(requestBytes),
  request_b64: requestB64,

  signature_algorithm: "Ed25519",
  signature_b64: signature.toString("base64"),

  public_key_der_b64: EXPECTED_PUBLIC_KEY_DER_B64,
  public_key_fingerprint_sha256: EXPECTED_FINGERPRINT,

  authority: {
    repository: process.env.GITHUB_REPOSITORY,
    environment: "coverage-approval-production",
    requester,
    issue_number: event.issue.number,
    issue_url: event.issue.html_url,
  },

  github_evidence: {
    run_id: process.env.GITHUB_RUN_ID,
    run_attempt: process.env.GITHUB_RUN_ATTEMPT,
    workflow: process.env.GITHUB_WORKFLOW,
    workflow_sha: process.env.GITHUB_SHA,
    server_url: process.env.GITHUB_SERVER_URL,
  },
};

await fs.mkdir("out", { recursive: true });

await fs.writeFile(
  "out/coverage-waiver-detached-signature.json",
  `${JSON.stringify(artifact, null, 2)}\n`,
  {
    encoding: "utf8",
    mode: 0o600,
  }
);

console.log("AUTHORITY_SIGNATURE_CREATED");
console.log(`request_sha256=${artifact.request_sha256}`);
console.log(
  `public_key_fingerprint_sha256=${artifact.public_key_fingerprint_sha256}`
);
console.log(`requester=${requester}`);
console.log(`issue_number=${event.issue.number}`);
console.log("private_key_output=false");
