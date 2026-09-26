import { IDKit, proofOfHuman } from "@worldcoin/idkit-core";
import QRCode from "qrcode";
import "./style.css";

const eventInput = document.querySelector<HTMLInputElement>("#event-id")!;
const startButton = document.querySelector<HTMLButtonElement>("#start")!;
const status = document.querySelector<HTMLElement>("#status")!;
const appStep = document.querySelector<HTMLElement>("#app-step")!;
const appLink = document.querySelector<HTMLAnchorElement>("#app-link")!;
const worldStep = document.querySelector<HTMLElement>("#world-step")!;
const worldLink = document.querySelector<HTMLAnchorElement>("#world-link")!;
const worldQr = document.querySelector<HTMLImageElement>("#world-qr")!;

interface PendingCheck {
  eventId: string;
  challenge: string;
  state: string;
  eventKey?: string;
  signal?: string;
}

function setStatus(message: string, kind: "normal" | "error" | "success" = "normal") {
  status.textContent = message;
  status.dataset.kind = kind;
}

function storageKey(state: string) { return `alcor/join/v1/${state}`; }

function save(check: PendingCheck) { localStorage.setItem(storageKey(check.state), JSON.stringify(check)); }

function load(state: string): PendingCheck | null {
  try {
    const value = localStorage.getItem(storageKey(state));
    return value ? JSON.parse(value) as PendingCheck : null;
  } catch { return null; }
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  const data = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(data.error ?? `Request failed (${response.status})`);
  return data;
}

async function start() {
  const eventId = eventInput.value.trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(eventId)) {
    setStatus("Enter a 32-byte registry event ID.", "error");
    return;
  }
  startButton.disabled = true;
  setStatus("Issuing a signing challenge…");
  try {
    const { challenge, expiresAt } = await post<{ challenge: string; expiresAt: string }>("/challenge", { eventId });
    const state = crypto.randomUUID();
    save({ eventId, challenge, state });
    const params = new URLSearchParams({ v: "1", p: "01", e: eventId, b: challenge, st: state });
    appLink.href = `beid://event-key-sign?${params.toString()}`;
    appStep.hidden = false;
    worldStep.hidden = true;
    setStatus(`Challenge expires at ${new Date(expiresAt).toLocaleTimeString()}. Open Beid to sign it.`);
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Could not issue a challenge.", "error");
  } finally { startButton.disabled = false; }
}

async function finishFromCallback() {
  const fragment = new URLSearchParams(location.hash.slice(1));
  if (!fragment.has("st")) return;
  const state = fragment.get("st") ?? "";
  const signature = fragment.get("sig") ?? "";
  const eventKey = fragment.get("k") ?? "";
  const address = fragment.get("a") ?? "";
  history.replaceState(null, "", location.pathname + location.search);
  const pending = load(state);
  if (!pending || !/^0x[0-9a-fA-F]{130}$/.test(signature) || !/^0x[0-9a-fA-F]{66}$/.test(eventKey) || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
    setStatus("The app callback did not match a pending check. Start again.", "error");
    return;
  }
  eventInput.value = pending.eventId;
  appStep.hidden = true;
  startButton.disabled = true;
  setStatus("Checking the event-key signature…");
  try {
    const { signal } = await post<{ signal: string }>("/bind", {
      eventId: pending.eventId, eventKey, challenge: pending.challenge, appSignature: signature,
    });
    pending.signal = signal;
    pending.eventKey = eventKey;
    save(pending);
    await verifyWithWorld(pending);
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "Verification failed.", "error");
  } finally { startButton.disabled = false; }
}

async function verifyWithWorld(check: PendingCheck) {
  if (!check.signal || !check.eventKey) throw new Error("The event key has not been bound.");
  const configResponse = await fetch(`/config?eventId=${encodeURIComponent(check.eventId)}`);
  if (!configResponse.ok) throw new Error("World ID configuration is unavailable.");
  const config = await configResponse.json() as { appId: string; rpId: string; action: string; environment: "staging" | "production" };
  const rpContext = await post<{ rp_id: string; nonce: string; created_at: number; expires_at: number; signature: string }>(
    "/rp-context", { eventId: check.eventId },
  );
  if (rpContext.rp_id !== config.rpId) throw new Error("RP context does not match configuration.");
  const request = await IDKit.request({
    app_id: config.appId as `app_${string}`,
    action: config.action,
    rp_context: rpContext,
    allow_legacy_proofs: false,
    environment: config.environment,
  }).preset(proofOfHuman({ signal: check.signal }));
  worldLink.href = request.connectorURI;
  worldQr.src = await QRCode.toDataURL(request.connectorURI, { margin: 1, width: 380 });
  worldStep.hidden = false;
  setStatus("Waiting for World ID verification…");
  const completion = await request.pollUntilCompletion();
  if (!completion.success) throw new Error("World ID verification was not completed.");
  const { credential } = await post<{ credential: { eventKeyAddress: string } }>("/verify", {
    eventId: check.eventId, eventKey: check.eventKey, challenge: check.challenge, idkitResult: completion.result,
  });
  localStorage.removeItem(storageKey(check.state));
  worldStep.hidden = true;
  setStatus(`Verified. Your event key ${credential.eventKeyAddress} is published for this event.`, "success");
}

startButton.addEventListener("click", () => { void start(); });
void finishFromCallback();
