import { hashSignal } from "@worldcoin/idkit-core/hashing";
import { signRequest } from "@worldcoin/idkit-core/signing";
import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { concat, getAddress, hexToBytes, keccak256, recoverAddress, sha256, toBytes, toHex, type Hex } from "viem";

export interface Env {
  DB: D1Database;
  ASSETS?: { fetch(request: Request): Promise<Response> };
  WORLD_APP_ID: string;
  WORLD_RP_ID: string;
  WORLD_ACTION: string;
  WORLD_ENV: "staging" | "production";
  WORLD_STAGING_VERIFICATION_TOKEN?: string;
  WORLD_RP_SIGNING_KEY?: Hex;
  ATTESTATION_KEY?: Hex;
}

interface WorldVerification {
  status: number;
  body: unknown;
  diagnostics?: {
    content_type: string | null;
    server: string | null;
    cf_ray: string | null;
    cf_mitigated: string | null;
    x_vercel_id: string | null;
    x_vercel_error: string | null;
    world_body_json: boolean;
    body_preview: string | null;
  };
}

interface Dependencies {
  worldVerify?: (result: unknown, rpId: string) => Promise<WorldVerification>;
  now?: () => number;
  randomBytes?: () => Uint8Array;
}

interface BoundChallenge {
  challenge: string;
  event_id: string;
  expires_at: number;
  event_key: string | null;
  event_key_address: string | null;
  app_signature: string | null;
  signal: string | null;
  bound_at: number | null;
}

interface CredentialEntry {
  eventKey: string;
  eventKeyAddress: string;
  nullifierHash: string;
  verifiedAt: string;
  challenge: string;
  appSignature: string;
  proofDigest: string;
  attestation: { algorithm: "Ed25519"; publicKey: string; signature: string };
}

const EVENT_ID = /^0x[0-9a-fA-F]{64}$/;
const KEY = /^0x[0-9a-fA-F]{66}$/;
const SIGNATURE = /^0x[0-9a-fA-F]{130}$/;
const NULLIFIER = /^0x[0-9a-fA-F]{1,64}$/;
const DOMAIN = toBytes("beid/event-key-sign/v1");
const TEN_MINUTES = 600_000;
const API_PATHS = new Set(["/challenge", "/rp-context", "/bind", "/verify", "/credentials", "/config"]);
const CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function fail(error: string, status: number): Response { return json({ error }, status); }

function object(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

async function bodyOf(request: Request): Promise<Record<string, unknown> | null> {
  try { const value = await request.json(); return object(value) ? value : null; }
  catch { return null; }
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}

function normalizedEvent(value: unknown, env: Env): Hex | null {
  if (typeof value !== "string" || !EVENT_ID.test(value)) return null;
  const eventId = value.toLowerCase() as Hex;
  if (env.WORLD_ACTION !== `mizar-${eventId.slice(2, 10)}`) return null;
  return eventId;
}

function normalizedKey(value: unknown): Hex | null {
  if (typeof value !== "string" || !KEY.test(value)) return null;
  try { secp256k1.ProjectivePoint.fromHex(value.slice(2)); return value.toLowerCase() as Hex; }
  catch { return null; }
}

export function eventKeyAddress(eventKey: string): string {
  if (!KEY.test(eventKey)) throw new Error("invalid event key");
  const uncompressed = secp256k1.ProjectivePoint.fromHex(eventKey.slice(2)).toRawBytes(false);
  return getAddress(`0x${keccak256(uncompressed.slice(1)).slice(-40)}`);
}

export function bindingDigest(eventId: string, challenge: string): Hex {
  if (!EVENT_ID.test(eventId) || !EVENT_ID.test(challenge)) throw new Error("invalid binding input");
  const message = concat([new Uint8Array([0xff]), DOMAIN, new Uint8Array([0, 1]), hexToBytes(eventId as Hex), hexToBytes(challenge as Hex)]);
  return sha256(message);
}

async function validAppSignature(eventId: string, challenge: string, eventKey: string, signature: string): Promise<boolean> {
  if (!SIGNATURE.test(signature)) return false;
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  const v = Number.parseInt(signature.slice(130, 132), 16);
  if (s === 0n || s > CURVE_ORDER / 2n || (v !== 27 && v !== 28)) return false;
  try {
    const recovered = await recoverAddress({ hash: bindingDigest(eventId, challenge), signature: signature as Hex });
    return recovered === eventKeyAddress(eventKey);
  } catch { return false; }
}

function bindingSignal(eventId: Hex, address: string, challenge: string): Hex {
  // IDKit hashes this value once more (keccak256 >> 8), producing the spec's hashToField(keccak256(tuple)).
  return keccak256(concat([hexToBytes(eventId), hexToBytes(address as Hex), hexToBytes(challenge as Hex)]));
}

/** Only short snake_case codes without echoed sensitive values may reach clients. */
function worldErrorCode(value: unknown, sensitive: unknown[]): string | null {
  return typeof value === "string" && value.length <= 64 && /^[a-z]+(?:_[a-z]+)*$/.test(value) &&
    diagnosticText(value, sensitive) === value ? value : null;
}

function normalizeNullifier(value: unknown): Hex | null {
  if (typeof value !== "string" || !NULLIFIER.test(value)) return null;
  return `0x${BigInt(value).toString(16).padStart(64, "0")}` as Hex;
}

function credentialSignature(entry: Omit<CredentialEntry, "attestation">, key: Hex): CredentialEntry["attestation"] {
  if (!EVENT_ID.test(key)) throw new Error("ATTESTATION_KEY must be a 32-byte Ed25519 seed");
  const privateKey = hexToBytes(key);
  const message = toBytes(`alcor/credential/v1\0${canonical(entry)}`);
  return {
    algorithm: "Ed25519",
    publicKey: toHex(ed25519.getPublicKey(privateKey)),
    signature: toHex(ed25519.sign(message, privateKey)),
  };
}

function diagnosticText(value: unknown, sensitive: unknown[]): string | null {
  if (typeof value !== "string") return null;
  function strings(item: unknown): string[] {
    if (typeof item === "string") return item ? [item] : [];
    if (typeof item === "number") return [String(item)];
    if (Array.isArray(item)) return item.flatMap(strings);
    if (object(item)) return Object.values(item).flatMap(strings);
    return [];
  }
  // Upstream text can echo submitted data. Redact before truncating or logging.
  for (const secret of strings(sensitive).sort((a, b) => b.length - a.length)) {
    value = (value as string).split(secret).join("[redacted]");
  }
  return (value as string).replace(/0x[0-9a-f]+/gi, "[redacted]").replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 512);
}

async function defaultWorldVerify(result: unknown, env: Env): Promise<WorldVerification> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json",
    "user-agent": "alcor-human-check/1.0 (+https://github.com/levarac/alcor)",
  };
  if (env.WORLD_ENV === "staging" && env.WORLD_STAGING_VERIFICATION_TOKEN) {
    headers["x-staging-verification-token"] = env.WORLD_STAGING_VERIFICATION_TOKEN;
  }
  const response = await fetch(`https://developer.world.org/api/v4/verify/${encodeURIComponent(env.WORLD_RP_ID)}`, {
    method: "POST",
    headers,
    body: JSON.stringify(result),
  });
  let body: unknown;
  let text = "";
  let bodyJson = false;
  try {
    text = await response.text();
    body = JSON.parse(text);
    bodyJson = true;
  }
  catch { body = null; }
  return { status: response.status, body, ...(!response.ok ? { diagnostics: {
    content_type: response.headers.get("content-type"),
    server: response.headers.get("server"),
    cf_ray: response.headers.get("cf-ray"),
    cf_mitigated: response.headers.get("cf-mitigated"),
    x_vercel_id: response.headers.get("x-vercel-id"),
    x_vercel_error: response.headers.get("x-vercel-error"),
    world_body_json: bodyJson,
    // Keep the text intact until echoed sensitive values have been redacted.
    body_preview: bodyJson ? null : text,
  } } : {}) };
}

export function createApp(dependencies: Dependencies = {}) {
  const now = dependencies.now ?? Date.now;
  const randomBytes = dependencies.randomBytes ?? (() => crypto.getRandomValues(new Uint8Array(32)));

  return {
    async fetch(request: Request, env: Env): Promise<Response> {
      const url = new URL(request.url);
      const path = url.pathname;
      if (!API_PATHS.has(path)) {
        if ((request.method === "GET" || request.method === "HEAD") && env.ASSETS) {
          return env.ASSETS.fetch(request);
        }
        return fail("not_found", 404);
      }
      if (path === "/credentials" && request.method === "GET") {
        const eventId = normalizedEvent(url.searchParams.get("eventId"), env);
        if (!eventId) return fail("invalid_event", 400);
        const rows = await env.DB.prepare("SELECT event_key, event_key_address, nullifier_hash, verified_at, challenge, app_signature, proof_digest, attestation FROM credentials WHERE event_id = ? ORDER BY verified_at, event_key")
          .bind(eventId).all<Record<string, string>>();
        return json({ eventId, credentials: rows.results.map(row => ({
          eventKey: row.event_key, eventKeyAddress: row.event_key_address, nullifierHash: row.nullifier_hash,
          verifiedAt: row.verified_at, challenge: row.challenge, appSignature: row.app_signature,
          proofDigest: row.proof_digest, attestation: JSON.parse(row.attestation),
        })) });
      }
      if (path === "/config" && request.method === "GET") {
        if (!normalizedEvent(url.searchParams.get("eventId"), env)) return fail("invalid_event", 400);
        return json({ appId: env.WORLD_APP_ID, rpId: env.WORLD_RP_ID, action: env.WORLD_ACTION, environment: env.WORLD_ENV });
      }
      if (request.method !== "POST") return fail("not_found", 404);
      const input = await bodyOf(request);
      if (!input) return fail("invalid_json", 400);
      const eventId = normalizedEvent(input.eventId, env);
      if (!eventId) return fail("invalid_event", 400);

      if (path === "/challenge") {
        const bytes = randomBytes();
        if (bytes.length !== 32) return fail("random_source_invalid", 503);
        const challenge = toHex(bytes);
        const expiresAt = now() + TEN_MINUTES;
        await env.DB.prepare("INSERT INTO challenges (challenge, event_id, expires_at) VALUES (?, ?, ?)")
          .bind(challenge, eventId, expiresAt).run();
        return json({ challenge, expiresAt: new Date(expiresAt).toISOString() });
      }

      if (path === "/rp-context") {
        if (!env.WORLD_RP_SIGNING_KEY) return fail("rp_signing_key_unconfigured", 503);
        try {
          const signed = signRequest({ signingKeyHex: env.WORLD_RP_SIGNING_KEY, action: env.WORLD_ACTION });
          return json({ rp_id: env.WORLD_RP_ID, signature: signed.sig, nonce: signed.nonce, created_at: signed.createdAt, expires_at: signed.expiresAt });
        } catch { return fail("rp_signing_failed", 503); }
      }

      if (path === "/bind") {
        const eventKey = normalizedKey(input.eventKey);
        const challenge = typeof input.challenge === "string" && EVENT_ID.test(input.challenge) ? input.challenge.toLowerCase() : null;
        const signature = typeof input.appSignature === "string" ? input.appSignature.toLowerCase() : "";
        if (!eventKey || !challenge || !SIGNATURE.test(signature)) return fail("invalid_binding", 400);
        const row = await env.DB.prepare("SELECT * FROM challenges WHERE challenge = ? AND event_id = ?")
          .bind(challenge, eventId).first<BoundChallenge>();
        if (!row) return fail("unknown_challenge", 404);
        if (row.expires_at <= now()) return fail("expired_challenge", 410);
        if (row.bound_at !== null) return fail("used_challenge", 409);
        if (!await validAppSignature(eventId, challenge, eventKey, signature)) return fail("invalid_app_signature", 400);
        const address = eventKeyAddress(eventKey);
        const signal = bindingSignal(eventId, address, challenge);
        const update = await env.DB.prepare("UPDATE challenges SET event_key = ?, event_key_address = ?, app_signature = ?, signal = ?, bound_at = ? WHERE challenge = ? AND bound_at IS NULL AND expires_at > ?")
          .bind(eventKey, address, signature, signal, now(), challenge, now()).run();
        if (update.meta.changes !== 1) return fail("used_challenge", 409);
        return json({ signal });
      }

      if (path === "/verify") {
        const eventKey = normalizedKey(input.eventKey);
        const challenge = typeof input.challenge === "string" && EVENT_ID.test(input.challenge) ? input.challenge.toLowerCase() : null;
        if (!eventKey || !challenge || !object(input.idkitResult)) return fail("invalid_verification", 400);
        const row = await env.DB.prepare("SELECT * FROM challenges WHERE event_id = ? AND event_key = ? AND challenge = ? AND bound_at IS NOT NULL")
          .bind(eventId, eventKey, challenge).first<BoundChallenge>();
        if (!row) return fail("unbound_key", 409);
        if (row.expires_at <= now()) return fail("expired_challenge", 410);
        const used = await env.DB.prepare("SELECT 1 FROM credentials WHERE challenge = ?").bind(challenge).first();
        if (used) return fail("used_challenge", 409);
        const result = input.idkitResult;
        const responses = result.responses;
        if (result.protocol_version !== "4.0" || result.action !== env.WORLD_ACTION || result.environment !== env.WORLD_ENV ||
            !Array.isArray(responses) || responses.length !== 1 || !object(responses[0]) || responses[0].identifier !== "proof_of_human" ||
            typeof responses[0].signal_hash !== "string" || responses[0].signal_hash.toLowerCase() !== hashSignal(row.signal!).toLowerCase()) {
          return fail("wrong_signal_or_request", 400);
        }
        const nullifier = normalizeNullifier(responses[0].nullifier);
        if (!nullifier || !Array.isArray(responses[0].proof)) return fail("invalid_proof_shape", 400);
        if (env.WORLD_ENV === "staging" && !env.WORLD_STAGING_VERIFICATION_TOKEN) {
          console.error("World verification unavailable", { reason: "staging_token_missing" });
          return json({ error: "world_unavailable", reason: "staging_token_missing" }, 503);
        }
        let verified: WorldVerification;
        try {
          verified = dependencies.worldVerify
            ? await dependencies.worldVerify(result, env.WORLD_RP_ID)
            : await defaultWorldVerify(result, env);
        } catch {
          console.error("World verification unavailable", { reason: "request_failed" });
          return fail("world_unavailable", 502);
        }
        const world = verified.body;
        if (verified.status !== 200 || !object(world) || world.success !== true || world.action !== env.WORLD_ACTION || world.environment !== env.WORLD_ENV ||
            normalizeNullifier(world.nullifier) !== nullifier || !Array.isArray(world.results) || world.results.length !== 1 ||
            !object(world.results[0]) || world.results[0].success !== true || world.results[0].identifier !== "proof_of_human" ||
            normalizeNullifier(world.results[0].nullifier) !== nullifier) {
          const sensitive = [responses, result.nonce, row, env.WORLD_STAGING_VERIFICATION_TOKEN,
            env.WORLD_RP_SIGNING_KEY, env.ATTESTATION_KEY];
          const worldResults = object(world) && Array.isArray(world.results) ? world.results : [];
          const diagnostics = verified.diagnostics;
          const contentType = diagnosticText(diagnostics?.content_type, sensitive);
          console.error("World verification failed", {
            status: verified.status,
            code: diagnosticText(object(world) ? world.code : null, sensitive),
            detail: diagnosticText(object(world) ? world.detail : null, sensitive),
            results: worldResults.map((item) => object(item)
              ? { code: diagnosticText(item.code, sensitive), detail: diagnosticText(item.detail, sensitive) }
              : null),
            ...(diagnostics ? {
              content_type: contentType,
              server: diagnosticText(diagnostics.server, sensitive),
              cf_ray: diagnosticText(diagnostics.cf_ray, sensitive),
              cf_mitigated: diagnosticText(diagnostics.cf_mitigated, sensitive),
              x_vercel_id: diagnosticText(diagnostics.x_vercel_id, sensitive),
              x_vercel_error: diagnosticText(diagnostics.x_vercel_error, sensitive),
              world_body_json: diagnostics.world_body_json,
              body_preview: diagnosticText(diagnostics.body_preview, sensitive)?.slice(0, 200) ?? null,
            } : {}),
          });
          if (verified.status === 403 && object(world) && world.code === "environment_not_allowed") {
            return json({ error: "world_unavailable", reason: "environment_not_allowed" }, 503);
          }
          return json({
            error: "world_verification_failed",
            world_status: verified.status,
            world_code: worldErrorCode(object(world) ? world.code : null, sensitive),
            world_result_codes: worldResults.map((item) => worldErrorCode(object(item) ? item.code : null, sensitive)),
            ...(diagnostics?.world_body_json === false ? {
              world_body_json: false,
              ...(contentType !== null && contentType === diagnostics.content_type ? { content_type: contentType } : {}),
            } : {}),
          }, verified.status >= 500 ? 502 : 400);
        }
        if (!env.ATTESTATION_KEY) return fail("attestation_key_unconfigured", 503);
        if (row.expires_at <= now()) return fail("expired_challenge", 410);
        const unsigned = {
          eventKey, eventKeyAddress: row.event_key_address!, nullifierHash: nullifier,
          verifiedAt: new Date(now()).toISOString(), challenge: row.challenge,
          appSignature: row.app_signature!, proofDigest: sha256(toBytes(canonical(result))),
        };
        let attestation: CredentialEntry["attestation"];
        try { attestation = credentialSignature(unsigned, env.ATTESTATION_KEY); }
        catch { return fail("attestation_key_invalid", 503); }
        const entry: CredentialEntry = { ...unsigned, attestation };
        try {
          await env.DB.prepare("INSERT INTO credentials (event_id, event_key, event_key_address, nullifier_hash, verified_at, challenge, app_signature, proof_digest, attestation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(eventId, eventKey, entry.eventKeyAddress, nullifier, entry.verifiedAt, entry.challenge, entry.appSignature, entry.proofDigest, JSON.stringify(attestation)).run();
        } catch (error) {
          console.error("Credential insert failed", {
            message: String(error instanceof Error ? error.message : error).slice(0, 200),
            nullifierPrefix: nullifier.slice(0, 12),
          });
          return fail("credential_already_exists", 409);
        }
        return json({ credential: entry });
      }
      return fail("not_found", 404);
    },
  };
}

export default createApp();
