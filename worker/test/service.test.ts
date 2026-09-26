import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Miniflare } from "miniflare";
import { hashSignal } from "@worldcoin/idkit-core/hashing";
import { ed25519 } from "@noble/curves/ed25519";
import { bytesToHex, hexToBytes, sha256, toBytes, toHex, type Hex } from "viem";
import { secp256k1 } from "@noble/curves/secp256k1";
import { createApp, bindingDigest, eventKeyAddress, type Env } from "../src/index";
import vector from "./fixtures/app-signature-v1.json";
import fixture from "./fixtures/world-success-v4.json";
import signedFixture from "./fixtures/signed-credentials-v1.json";
import failures from "./fixtures/world-failures-v4.json";
import schema from "../migrations/0001_initial.sql?raw";

const now = Date.parse("2026-09-26T00:00:00.000Z");
const eventId = vector.eventId;
const eventKey = vector.eventKeyCompressed;
// Publicly reproducible TEST KEY ONLY; never use it for an event or funds.
const secondTestKey = hexToBytes(sha256(toBytes("ALCOR DETERMINISTIC SECOND EVENT TEST KEY ONLY")));
const secondKey = toHex(secp256k1.getPublicKey(secondTestKey, true));
const testSeed = sha256(new TextEncoder().encode("ALCOR DETERMINISTIC TEST ATTESTATION KEY ONLY"));
const stagingToken = "ALCOR_TEST_STAGING_TOKEN_ONLY";

let mf: Miniflare;
let env: Env;
let clock = now;
let verifyMock: ReturnType<typeof vi.fn>;
let app: ReturnType<typeof createApp>;
let challengeNumber = 0;

async function post(path: string, body: unknown) {
  return app.fetch(new Request(`http://localhost${path}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  }), env);
}

async function bind() {
  const issued = await post("/challenge", { eventId });
  expect(issued.status).toBe(200);
  const { challenge } = await issued.json() as { challenge: string };
  const response = await post("/bind", { eventId, eventKey, challenge, appSignature: vector.humanCheckBinding.signature });
  return { challenge, response };
}

function idkit(signal: string, overrides: Record<string, unknown> = {}) {
  return {
    ...fixture.idkitResult,
    responses: [{ ...fixture.idkitResult.responses[0], signal_hash: hashSignal(signal), ...overrides }],
  };
}

beforeEach(async () => {
  clock = now;
  challengeNumber = 0;
  mf = new Miniflare({ modules: true, script: "export default { fetch(){ return new Response('ok') } }", d1Databases: { DB: "DB" } });
  const db = await mf.getD1Database("DB");
  for (const statement of schema.split(";").map(part => part.trim()).filter(Boolean)) {
    await db.prepare(statement).run();
  }
  env = {
    DB: db,
    WORLD_APP_ID: "app_FAKE_TEST",
    WORLD_RP_ID: "rp_FAKE_TEST",
    WORLD_ACTION: "mizar-996ab4d7",
    WORLD_ENV: "staging",
    WORLD_STAGING_VERIFICATION_TOKEN: stagingToken,
    WORLD_RP_SIGNING_KEY: testSeed,
    ATTESTATION_KEY: testSeed,
  };
  verifyMock = vi.fn(async () => ({ status: 200, body: fixture.worldResponse }));
  app = createApp({ worldVerify: verifyMock, now: () => clock, randomBytes: () => {
    challengeNumber++;
    return new Uint8Array(32).fill(0xa0 + challengeNumber);
  } });
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  await mf.dispose();
});

describe("purpose 0x01 golden vector", () => {
  it("builds the exact 89-byte message digest and recovers the compressed event key", () => {
    expect(bindingDigest(eventId, vector.humanCheckBinding.challenge)).toBe(vector.humanCheckBinding.digest);
    expect(eventKeyAddress(eventKey)).toBe(vector.eventKeyAddress);
  });
});

describe("human-check endpoints", () => {
  it("issues a random ten-minute challenge and rejects malformed event IDs", async () => {
    const response = await post("/challenge", { eventId });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ challenge: vector.humanCheckBinding.challenge, expiresAt: new Date(now + 600_000).toISOString() });
    expect((await post("/challenge", { eventId: "bad" })).status).toBe(400);
  });

  it("binds only the golden purpose 0x01 signature, then refuses replay", async () => {
    const { challenge, response } = await bind();
    expect(response.status).toBe(200);
    const { signal } = await response.json() as { signal: string };
    expect(signal).toMatch(/^0x[0-9a-f]{64}$/);
    expect(hashSignal(signal)).toMatch(/^0x[0-9a-f]{64}$/);
    expect((await post("/bind", { eventId, eventKey, challenge, appSignature: vector.humanCheckBinding.signature })).status).toBe(409);
  });

  it("rejects an invalid signature and an expired challenge", async () => {
    const challenge = (await (await post("/challenge", { eventId })).json() as { challenge: string }).challenge;
    expect((await post("/bind", { eventId, eventKey, challenge, appSignature: `0x${"00".repeat(65)}` })).status).toBe(400);
    clock += failures.expiredChallenge.advanceMs;
    expect((await post("/bind", { eventId, eventKey, challenge, appSignature: vector.humanCheckBinding.signature })).status).toBe(410);
  });

  it("returns a signed credential and publishes exactly the accepted key", async () => {
    const { challenge, response } = await bind();
    const { signal } = await response.json() as { signal: string };
    const result = idkit(signal);
    expect((await post("/verify", { eventId, eventKey, idkitResult: result })).status).toBe(400);
    expect(verifyMock).not.toHaveBeenCalled();
    const verified = await post("/verify", { eventId, eventKey, challenge, idkitResult: result });
    expect(verified.status).toBe(200);
    const credential = (await verified.json() as { credential: Record<string, unknown> }).credential;
    expect(verifyMock).toHaveBeenCalledWith(result, "rp_FAKE_TEST");
    expect(credential.eventKey).toBe(eventKey);
    expect(credential.nullifierHash).toBe(fixture.worldResponse.nullifier);
    expect(credential.proofDigest).toMatch(/^0x[0-9a-f]{64}$/);
    const attestation = credential.attestation as { algorithm: string; publicKey: string; signature: string };
    expect(attestation.algorithm).toBe("Ed25519");
    expect(attestation.publicKey).toBe(bytesToHex(ed25519.getPublicKey(hexToBytes(testSeed))));
    expect(attestation.signature).toMatch(/^0x[0-9a-f]{128}$/);
    const list = await app.fetch(new Request(`http://localhost/credentials?eventId=${eventId}`), env);
    expect(list.status).toBe(200);
    expect(await list.json()).toEqual(signedFixture.response);
    expect(signedFixture.testAttestationSeed).toBe(testSeed);
    const unsigned = Object.fromEntries(Object.entries(credential).filter(([key]) => key !== "attestation").sort(([a], [b]) => a.localeCompare(b)));
    expect(ed25519.verify(
      hexToBytes(attestation.signature as Hex),
      toBytes(`alcor/credential/v1\0${JSON.stringify(unsigned)}`),
      hexToBytes(attestation.publicKey as Hex),
    )).toBe(true);
    expect((await post("/verify", { eventId, eventKey, challenge, idkitResult: result })).status).toBe(409);
    expect(verifyMock).toHaveBeenCalledTimes(1);
  });

  it("rejects wrong signal before calling World and invalid World proof", async () => {
    const { challenge, response } = await bind();
    const { signal } = await response.json() as { signal: string };
    expect((await post("/verify", { eventId, eventKey, challenge, idkitResult: idkit(signal, failures.wrongSignal) })).status).toBe(400);
    expect(verifyMock).not.toHaveBeenCalled();
    verifyMock.mockResolvedValueOnce(failures.invalidProof);
    expect((await post("/verify", { eventId, eventKey, challenge, idkitResult: idkit(signal) })).status).toBe(400);
  });

  it("verifies challenge A after the same key has also bound challenge B", async () => {
    const first = await bind();
    const signalA = (await first.response.json() as { signal: string }).signal;
    clock += 1_000;
    const challengeB = (await (await post("/challenge", { eventId })).json() as { challenge: string }).challenge;
    const signatureB = secp256k1.sign(
      hexToBytes(bindingDigest(eventId, challengeB)),
      hexToBytes(vector.testPrivateKey as Hex),
      { lowS: true },
    );
    const appSignatureB = `${toHex(signatureB.toCompactRawBytes())}${(27 + signatureB.recovery).toString(16)}`;
    const boundB = await post("/bind", { eventId, eventKey, challenge: challengeB, appSignature: appSignatureB });
    expect(boundB.status).toBe(200);
    expect((await boundB.json() as { signal: string }).signal).not.toBe(signalA);

    const result = await post("/verify", { eventId, eventKey, challenge: first.challenge, idkitResult: idkit(signalA) });
    expect(result.status).toBe(200);
    expect((await result.json() as { credential: { challenge: string } }).credential.challenge).toBe(first.challenge);
  });

  it("rejects a second key for the same nullifier and expired verification", async () => {
    const { challenge, response } = await bind();
    const { signal } = await response.json() as { signal: string };
    expect((await post("/verify", { eventId, eventKey, challenge, idkitResult: idkit(signal) })).status).toBe(200);
    const secondChallenge = (await (await post("/challenge", { eventId })).json() as { challenge: string }).challenge;
    const digest = bindingDigest(eventId, secondChallenge);
    const signed = secp256k1.sign(hexToBytes(digest), secondTestKey, { lowS: true });
    const secondSignature = `${toHex(signed.toCompactRawBytes())}${(27 + signed.recovery).toString(16)}`;
    const secondBind = await post("/bind", { eventId, eventKey: secondKey, challenge: secondChallenge, appSignature: secondSignature });
    expect(secondBind.status).toBe(200);
    const secondSignal = (await secondBind.json() as { signal: string }).signal;
    expect((await post("/verify", { eventId, eventKey: secondKey, challenge: secondChallenge, idkitResult: idkit(secondSignal, failures.duplicateNullifier) })).status).toBe(409);
    clock += failures.expiredChallenge.advanceMs;
    expect((await post("/verify", { eventId, eventKey, challenge, idkitResult: idkit(signal) })).status).toBe(410);
  });

  it("returns public IDKit configuration and a backend RP signature without exposing keys", async () => {
    const config = await app.fetch(new Request(`http://localhost/config?eventId=${eventId}`), env);
    expect(config.status).toBe(200);
    expect(await config.json()).toEqual({ appId: "app_FAKE_TEST", rpId: "rp_FAKE_TEST", action: "mizar-996ab4d7", environment: "staging" });
    const signed = await post("/rp-context", { eventId });
    expect(signed.status).toBe(200);
    const body = await signed.json() as Record<string, unknown>;
    expect(body).toHaveProperty("signature");
    expect(body.rp_id).toBe("rp_FAKE_TEST");
    expect(body).toHaveProperty("nonce");
    expect(body).not.toHaveProperty("signingKeyHex");
  });
});

describe("World verification diagnostics and staging access", () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let errorLog: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    app = createApp({ now: () => clock, randomBytes: () => new Uint8Array(32).fill(0xa1) });
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  async function prepareVerification() {
    const { challenge, response } = await bind();
    const { signal } = await response.json() as { signal: string };
    const result = { ...idkit(signal), environment: env.WORLD_ENV };
    return { signal, result, body: { eventId, eventKey, challenge, idkitResult: result } };
  }

  it.each(["staging", "production"] as const)("sends the staging token only in staging: %s", async environment => {
    env.WORLD_ENV = environment;
    const { result, body } = await prepareVerification();
    fetchMock.mockResolvedValueOnce(Response.json({ ...fixture.worldResponse, environment }));
    expect((await post("/verify", body)).status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://developer.world.org/api/v4/verify/rp_FAKE_TEST");
    expect(new Headers(init.headers).get("x-staging-verification-token")).toBe(environment === "staging" ? stagingToken : null);
    expect(JSON.parse(init.body)).toEqual(result);
    expect(errorLog).not.toHaveBeenCalled();
  });

  it("fails closed without a staging token before calling World", async () => {
    delete env.WORLD_STAGING_VERIFICATION_TOKEN;
    const { body } = await prepareVerification();
    const response = await post("/verify", body);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "world_unavailable", reason: "staging_token_missing" });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(errorLog).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(errorLog.mock.calls)).toContain("staging_token_missing");
    expect(JSON.stringify(errorLog.mock.calls)).not.toContain(stagingToken);
  });

  it.each([
    [failures.environmentNotAllowed, 503, { error: "world_unavailable", reason: "environment_not_allowed" }],
    [failures.invalidProof, 400, { error: "world_verification_failed" }],
  ])("logs safe diagnostics for World response %j", async (failure, expectedStatus, expectedBody) => {
    const { signal, result, body } = await prepareVerification();
    fetchMock.mockResolvedValueOnce(Response.json(failure.body, { status: failure.status }));
    const response = await post("/verify", body);
    expect(response.status).toBe(expectedStatus);
    expect(await response.json()).toEqual(expectedBody);
    expect(errorLog).toHaveBeenCalledTimes(1);
    const logged = JSON.stringify(errorLog.mock.calls);
    expect(logged).toContain(String(failure.status));
    expect(logged).toContain(failure.body.code);
    expect(logged).toContain(failure.body.detail);
    for (const value of [stagingToken, testSeed, eventKey, signal, result.nonce, result.responses[0].signal_hash,
      result.responses[0].nullifier, ...result.responses[0].proof]) {
      expect(logged).not.toContain(value);
    }
    const credentials = await app.fetch(new Request(`http://localhost/credentials?eventId=${eventId}`), env);
    expect((await credentials.json() as { credentials: unknown[] }).credentials).toEqual([]);
  });

  it("redacts sensitive values echoed inside World error details", async () => {
    const { signal, result, body } = await prepareVerification();
    const sensitive = [stagingToken, testSeed, eventKey, signal, body.challenge, result.nonce,
      result.responses[0].signal_hash, result.responses[0].nullifier, ...result.responses[0].proof];
    fetchMock.mockResolvedValueOnce(Response.json({
      ...failures.invalidProof.body,
      detail: `Invalid proof: ${sensitive.join(" ")}`,
      proof: result.responses[0].proof,
      token: stagingToken,
    }, { status: 400 }));
    expect((await post("/verify", body)).status).toBe(400);
    const logged = JSON.stringify(errorLog.mock.calls);
    expect(logged).toContain("invalid_proof");
    expect(logged).toContain("Invalid proof:");
    expect(logged).toContain("[redacted]");
    for (const value of sensitive) expect(logged).not.toContain(value);
  });
});

describe("static assets alongside the API", () => {
  function withAssets() {
    const fetch = vi.fn(async (request: Request) => {
      const path = new URL(request.url).pathname;
      if (path === "/" || path === "/assets/main.js") {
        return new Response(request.method === "HEAD" ? null : path === "/" ? "<h1>Join Alcor</h1>" : "console.log('join')", {
          headers: { "content-type": path === "/" ? "text/html" : "text/javascript" },
        });
      }
      return new Response(null, { status: 404 });
    });
    const bindings = { ...env, ASSETS: { fetch } };
    return { fetch, bindings };
  }

  it("serves the join page, bundled assets and HEAD requests through the asset binding", async () => {
    const { bindings } = withAssets();
    const page = await app.fetch(new Request("http://localhost/"), bindings);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain("Join Alcor");
    const script = await app.fetch(new Request("http://localhost/assets/main.js"), bindings);
    expect(script.headers.get("content-type")).toBe("text/javascript");
    expect(await script.text()).toContain("console.log");
    const head = await app.fetch(new Request("http://localhost/", { method: "HEAD" }), bindings);
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
  });

  it("preserves JSON API responses and errors instead of falling through to HTML", async () => {
    const { fetch, bindings } = withAssets();
    for (const path of ["/config", "/credentials"]) {
      const response = await app.fetch(new Request(`http://localhost${path}?eventId=${eventId}`), bindings);
      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain("application/json");
    }
    expect((await app.fetch(new Request("http://localhost/config?eventId=bad"), bindings)).status).toBe(400);
    for (const path of ["/challenge", "/bind", "/rp-context", "/verify"]) {
      const response = await app.fetch(new Request(`http://localhost${path}`, { method: "POST", body: "{}" }), bindings);
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "invalid_event" });
    }
    const wrongMethod = await app.fetch(new Request("http://localhost/verify"), bindings);
    expect(wrongMethod.status).toBe(404);
    expect(await wrongMethod.json()).toEqual({ error: "not_found" });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("keeps missing assets and unknown POST paths as 404", async () => {
    const { fetch, bindings } = withAssets();
    expect((await app.fetch(new Request("http://localhost/missing.js"), bindings)).status).toBe(404);
    expect(fetch).toHaveBeenCalledTimes(1);
    const response = await app.fetch(new Request("http://localhost/missing", { method: "POST", body: "not JSON" }), bindings);
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_found" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
