import { IDKit, proofOfHuman, hashSignal } from "@worldcoin/idkit-core";
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
const panel = document.querySelector<HTMLElement>("#check-panel")!;
const title = document.querySelector<HTMLElement>("#check-title")!;
const eventDisplay = document.querySelector<HTMLElement>("#event-display")!;
const keyDisplay = document.querySelector<HTMLElement>("#event-key")!;
const keyPlaceholder = document.querySelector<HTMLElement>("#key-placeholder")!;
const keyCaption = document.querySelector<HTMLElement>("#key-caption")!;
const purpose = document.querySelector<HTMLElement>("#purpose")!;
const startLabel = document.querySelector<HTMLElement>("#start-label")!;
const stateLabel = document.querySelector<HTMLElement>("#state-label-text")!;
const pendingNote = document.querySelector<HTMLElement>("#pending-note")!;
const completionNote = document.querySelector<HTMLElement>("#completion-note")!;
const eventEditor = document.querySelector<HTMLDetailsElement>("#event-editor")!;
const challengeExpiry = document.querySelector<HTMLElement>("#challenge-expiry")!;

type Screen = "start" | "issuing" | "waiting-app" | "checking" | "world" | "verified" | "already" | "expired" | "world-failed" | "unavailable" | "invalid-event" | "invalid-callback";
type ScreenContent = { label: string; title: string; description: string; step: number; tone?: "error" | "success" };
const screens: Record<Screen, ScreenContent> = {
  start: { label: "Ready when you are", title: "Start with your event key.", description: "Sign a request in the app, then verify with World ID to receive your event credential.", step: 1 },
  issuing: { label: "Preparing your check", title: "Getting your request ready.", description: "Creating a one-time signing request for this event.", step: 1 },
  "waiting-app": { label: "Waiting for your signature", title: "Your next step is in the app.", description: "Open the app, confirm this event-key request, then return here to continue.", step: 1 },
  checking: { label: "Signature received", title: "Checking your event key.", description: "Your signature is being checked before World ID verification begins.", step: 2 },
  world: { label: "Waiting for World ID", title: "One person. One World ID.", description: "Complete the human check in World App, then return here for your event credential.", step: 2 },
  verified: { label: "Verified · Credential issued", title: "You’re ready for this event.", description: "Your World ID is linked to the event key shown here, and its credential has been issued.", step: 3, tone: "success" },
  already: { label: "A credential already exists", title: "Already linked for this event.", description: "One person can link only one key per event; return to the app and use the key you first verified.", step: 3, tone: "error" },
  expired: { label: "Challenge expired", title: "Let’s start a fresh check.", description: "This signing request has expired; start a new check and sign the new request in the app.", step: 1, tone: "error" },
  "world-failed": { label: "World ID check unsuccessful", title: "We couldn’t verify your World ID.", description: "World ID verification did not complete; start a new check and follow the prompts in World App.", step: 2, tone: "error" },
  unavailable: { label: "Service unavailable", title: "Please try again later.", description: "The verification service could not be reached; try again later or contact the event organizer.", step: 2, tone: "error" },
  "invalid-event": { label: "Check the event ID", title: "This event ID isn’t valid.", description: "The event ID must be 0x followed by 64 hexadecimal characters; check it with the event organizer and try again.", step: 1, tone: "error" },
  "invalid-callback": { label: "Signature not accepted", title: "Let’s try signing again.", description: "The app signature could not be matched to this check; start again and sign the new request in the app.", step: 1, tone: "error" },
};

// Presentation only: preserve the full value and allow wrapping at four-digit boundaries.
function showHex(element: HTMLElement, value: string) {
  element.replaceChildren();
  if (!/^0x[0-9a-fA-F]+$/.test(value)) { element.textContent = value; return; }
  const groups = value.slice(2).match(/.{1,4}/g) ?? [];
  groups.forEach((group, index) => {
    if (index > 0) element.append(document.createElement("wbr"));
    element.append(document.createTextNode(`${index === 0 ? "0x" : ""}${group}`));
  });
}

function checksumEventAddress(address: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return address;
  const lower = address.slice(2).toLowerCase();
  // IDKit returns keccak256 >> 8, padded to 32 bytes. EIP-55 uses only the
  // first 20 bytes, which remain intact after removing the leading zero byte.
  const hash = hashSignal(new TextEncoder().encode(lower)).slice(4);
  return `0x${Array.from(lower, (char, i) => parseInt(hash[i], 16) >= 8 ? char.toUpperCase() : char).join("")}`;
}

function showEventKey(address: string) {
  showHex(keyDisplay, checksumEventAddress(address));
  keyDisplay.hidden = !address;
  keyPlaceholder.hidden = !!address;
}

function updateEventPresentation() {
  const value = eventInput.value.trim();
  showHex(eventDisplay, value || "No event selected");
  const shortId = /^0x[0-9a-fA-F]{64}$/.test(value) ? `${value.slice(0, 6)}…${value.slice(-4)}` : "the selected event";
  purpose.replaceChildren(document.createTextNode("Link one World ID to this event key for event "));
  const event = document.createElement("span");
  event.className = "data";
  event.textContent = shortId;
  purpose.append(event, document.createTextNode("."));
}

function renderScreen(screen: Screen) {
  const content = screens[screen];
  panel.dataset.state = screen;
  panel.dataset.tone = content.tone ?? "normal";
  title.textContent = content.title;
  stateLabel.textContent = content.label;
  status.textContent = content.description;
  status.dataset.kind = content.tone ?? "normal";
  appStep.hidden = screen !== "waiting-app";
  worldStep.hidden = screen !== "world";
  const canStart = screen === "start" || (content.tone === "error" && screen !== "already");
  startButton.hidden = !canStart;
  startLabel.textContent = screen === "start" ? "Start human check" : screen === "unavailable" ? "Try again" : "Start a new check";
  pendingNote.hidden = screen !== "checking" && screen !== "issuing";
  completionNote.hidden = screen !== "verified";
  keyCaption.textContent = screen === "verified" ? "Credentialed for this event." : screen === "already" ? "The key submitted for this check." : "The key you use for this event.";
  eventEditor.style.visibility = canStart ? "visible" : "hidden";
  if (!canStart) eventEditor.open = false;
  document.querySelectorAll<HTMLElement>("[data-step]").forEach((item) => {
    const step = Number(item.dataset.step);
    item.classList.toggle("complete", step < content.step || screen === "verified");
    if (step === content.step) item.setAttribute("aria-current", "step");
    else item.removeAttribute("aria-current");
  });
  updateEventPresentation();
}

function errorScreen(message: string): Screen {
  if (message === "credential_already_exists") return "already";
  if (message === "expired_challenge") return "expired";
  if (message.startsWith("world_verification_failed") || message === "World ID verification was not completed.") return "world-failed";
  if (message === "invalid_event" || message === "Enter a 32-byte registry event ID.") return "invalid-event";
  if (["invalid_binding", "unknown_challenge", "used_challenge", "invalid_app_signature", "unbound_key", "wrong_signal_or_request", "invalid_proof_shape", "invalid_verification"].includes(message) || message.startsWith("The app callback")) return "invalid-callback";
  return "unavailable";
}

interface PendingCheck {
  eventId: string;
  challenge: string;
  state: string;
  eventKey?: string;
  signal?: string;
}

function setStatus(message: string, kind: "normal" | "error" | "success" = "normal") {
  if (kind === "error") { renderScreen(errorScreen(message)); return; }
  if (kind === "success") {
    const address = message.match(/0x[0-9a-fA-F]{40}/)?.[0];
    if (address) showEventKey(address);
    renderScreen("verified");
    return;
  }
  if (message.startsWith("Issuing")) { showEventKey(""); renderScreen("issuing"); }
  else if (message.startsWith("Challenge expires")) {
    challengeExpiry.textContent = `Sign before ${message.match(/^Challenge expires at (.+)\. Open /)?.[1] ?? "the request expires"}.`;
    renderScreen("waiting-app");
  } else if (message.startsWith("Checking")) renderScreen("checking");
  else if (message.startsWith("Waiting for World")) renderScreen("world");
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
  const data = await response.json() as T & { error?: string; world_code?: unknown; world_result_codes?: unknown };
  if (!response.ok) {
    if (data.error === "world_unavailable") {
      throw new Error("World ID verification is currently unavailable. Please try again later or contact the event organizer.");
    }
    if (data.error === "world_verification_failed") {
      const codes = [data.world_code, ...(Array.isArray(data.world_result_codes) ? data.world_result_codes : [])]
        .filter((code): code is string => typeof code === "string" && code.length <= 64 && /^[a-z]+(?:_[a-z]+)*$/.test(code));
      throw new Error(codes.length ? `${data.error}: ${codes.join(", ")}` : data.error);
    }
    throw new Error(data.error ?? `Request failed (${response.status})`);
  }
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
  showEventKey(address);
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

eventInput.addEventListener("input", updateEventPresentation);
updateEventPresentation();

// The preview is selected at build time; a production URL cannot enable it.
if (import.meta.env.MODE === "preview") {
  const fakeAddress = "0x52908400098527886E0F7030069857D2E4169EE7";
  const previewStates: Screen[] = ["start", "waiting-app", "checking", "world", "verified", "already", "expired", "world-failed", "unavailable", "issuing", "invalid-event", "invalid-callback"];
  const controls = document.createElement("aside");
  controls.className = "preview-controls";
  controls.setAttribute("aria-label", "Preview controls");
  const label = document.createElement("strong");
  label.textContent = "Preview: fake data";
  const select = document.createElement("select");
  select.setAttribute("aria-label", "Preview state");
  previewStates.forEach((state) => {
    const option = document.createElement("option");
    option.value = state;
    option.textContent = screens[state].label;
    select.append(option);
  });
  controls.append(label, select);
  document.body.prepend(controls);
  const showPreview = (state: Screen) => {
    select.value = state;
    showEventKey(["start", "waiting-app", "issuing", "invalid-event", "invalid-callback"].includes(state) ? "" : fakeAddress);
    challengeExpiry.textContent = "Sign before 14:30 · Preview time";
    renderScreen(state);
  };
  select.addEventListener("change", () => showPreview(select.value as Screen));
  startButton.addEventListener("click", () => showPreview("waiting-app"));
  appLink.addEventListener("click", (event) => { event.preventDefault(); showPreview("checking"); });
  worldLink.addEventListener("click", (event) => { event.preventDefault(); showPreview("verified"); });
  // An inert text QR cannot start a real verification request.
  void QRCode.toDataURL("Preview: fake data. No verification request.", { margin: 2, width: 380 }).then((src) => { worldQr.src = src; });
  worldQr.alt = "Preview QR code containing fake data, not a verification request";
  const requested = new URLSearchParams(location.search).get("state") as Screen;
  showPreview(previewStates.includes(requested) ? requested : "start");
} else {
  renderScreen("start");
  startButton.addEventListener("click", () => { void start(); });
  void finishFromCallback();
}
