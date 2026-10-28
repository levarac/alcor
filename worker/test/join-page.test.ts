import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { ModuleKind, ScriptTarget, transpileModule } from "typescript";
import { hashSignal } from "@worldcoin/idkit-core/hashing";
import { describe, expect, it, vi } from "vitest";

// Exercise the page's callback, HTTP error handling and rendering without a
// browser or live IDKit requests, using the existing Vitest/TypeScript setup.
const source = readFileSync(new URL("../../web/main.ts", import.meta.url), "utf8");
const page = transpileModule(source.replaceAll("import.meta.env.MODE", '"test"'), {
  compilerOptions: { module: ModuleKind.CommonJS, target: ScriptTarget.ES2022, esModuleInterop: true },
}).outputText;

function element() {
  const listeners = new Map<string, () => void>();
  return {
    value: "", hidden: false, disabled: false, open: false, textContent: "", href: "",
    dataset: {} as Record<string, string>, style: { visibility: "" },
    classList: { toggle: vi.fn() }, replaceChildren: vi.fn(), append: vi.fn(),
    setAttribute: vi.fn(), removeAttribute: vi.fn(), listeners,
    addEventListener: (event: string, listener: () => void) => listeners.set(event, listener),
  };
}

describe("join page verification failures", () => {
  it.each([
    { status: 503, error: "storage_unavailable", screen: "unavailable", restart: true },
    { status: 409, error: "credential_already_exists", screen: "already", restart: false },
  ])("renders $status $error with restart=$restart", async ({ status, error, screen, restart }) => {
    const elements = new Map<string, ReturnType<typeof element>>();
    const get = (selector: string) => {
      if (!elements.has(selector)) elements.set(selector, element());
      return elements.get(selector)!;
    };
    const eventId = `0x${"11".repeat(32)}`;
    const state = "pending-check";
    const stored = new Map([[`alcor/join/v1/${state}`, JSON.stringify({ eventId, state, challenge: `0x${"22".repeat(32)}` })]]);
    const fetch = vi.fn(async (path: string) => {
      if (path === "/bind") return Response.json({ signal: `0x${"33".repeat(32)}` });
      if (path.startsWith("/config?")) return Response.json({ appId: "app_TEST", rpId: "rp_TEST", action: "mizar-11111111", environment: "staging" });
      if (path === "/rp-context") return Response.json({ rp_id: "rp_TEST" });
      if (path === "/verify") return Response.json({ error }, { status });
      if (path === "/challenge") return Response.json({ challenge: `0x${"44".repeat(32)}`, expiresAt: "2026-10-25T00:10:00Z" });
      throw new Error(`Unexpected request: ${path}`);
    });
    const request = { connectorURI: "https://example.invalid/idkit", pollUntilCompletion: async () => ({ success: true, result: {} }) };
    const idkit = { hashSignal, proofOfHuman: vi.fn(), orbLegacy: vi.fn(), IDKit: { request: vi.fn(() => ({ preset: () => request })) } };
    runInNewContext(page, {
      exports: {},
      require: (name: string) => {
        if (name === "@worldcoin/idkit-core") return idkit;
        if (name === "qrcode") return { toDataURL: async () => "data:image/png;base64,TEST" };
        if (name === "./style.css") return {};
        throw new Error(`Unexpected import: ${name}`);
      },
      document: { querySelector: get, querySelectorAll: () => [], createElement: element, createTextNode: (text: string) => text },
      window: { addEventListener: vi.fn() }, history: { replaceState: vi.fn() },
      location: { hash: `#st=${state}&sig=0x${"aa".repeat(65)}&k=0x02${"bb".repeat(32)}&a=0x${"cc".repeat(20)}`, pathname: "/", search: "" },
      localStorage: { getItem: (key: string) => stored.get(key) ?? null, setItem: (key: string, value: string) => stored.set(key, value), removeItem: (key: string) => stored.delete(key) },
      crypto: { randomUUID: () => "new-check" }, fetch, URLSearchParams, TextEncoder,
    });

    await vi.waitFor(() => {
      expect(get("#check-panel").dataset.state).toBe(screen);
      expect(get("#start").disabled).toBe(false);
    });
    expect(fetch.mock.calls.map(([path]) => path)).toEqual(["/bind", `/config?eventId=${eventId}`, "/rp-context", "/verify"]);
    expect(get("#start").hidden).toBe(!restart);
    if (restart) {
      expect(get("#status").textContent).toContain("try again later");
      expect(get("#start-label").textContent).toBe("Try again");
      get("#start").listeners.get("click")!();
      await vi.waitFor(() => expect(get("#check-panel").dataset.state).toBe("waiting-app"));
      expect(fetch).toHaveBeenLastCalledWith("/challenge", expect.objectContaining({ body: JSON.stringify({ eventId }) }));
      expect(get("#app-link").href).toContain("beid://event-key-sign?");
    }
  });
});
