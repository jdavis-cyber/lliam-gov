// @vitest-environment jsdom
import { act } from "react";
import { createRoot } from "react-dom/client";
import { Link, MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  terminals: [] as Array<{ options: Record<string, unknown>; dispose: ReturnType<typeof vi.fn> }>,
  sockets: [] as Array<{ onopen: (() => void) | null; send: ReturnType<typeof vi.fn>; close: ReturnType<typeof vi.fn> }>,
  theme: { terminalBackground: "#000000" },
  header: { setEnd: vi.fn(), setTitle: vi.fn() },
}));
vi.mock("@xterm/xterm", () => ({
  Terminal: class {
    options: Record<string, unknown>;
    cols = 80;
    rows = 24;
    unicode = { activeVersion: "" };
    parser = { registerOscHandler: vi.fn() };
    dispose = vi.fn();
    open = vi.fn();
    focus = vi.fn();
    refresh = vi.fn();
    loadAddon = vi.fn();
    attachCustomKeyEventHandler = vi.fn();
    attachCustomWheelEventHandler = vi.fn();
    onData = vi.fn(() => ({ dispose: vi.fn() }));
    onResize = vi.fn(() => ({ dispose: vi.fn() }));
    constructor(options: Record<string, unknown>) {
      this.options = options;
      mocks.terminals.push(this);
    }
  },
}));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: class { fit = vi.fn(); } }));
vi.mock("@xterm/addon-unicode11", () => ({ Unicode11Addon: class {} }));
vi.mock("@xterm/addon-web-links", () => ({ WebLinksAddon: class {} }));
vi.mock("@xterm/addon-webgl", () => ({ WebglAddon: class { onContextLoss = vi.fn(); dispose = vi.fn(); } }));
vi.mock("@/themes", () => ({ useTheme: () => ({ theme: mocks.theme }) }));
vi.mock("@/contexts/usePageHeader", () => ({ usePageHeader: () => mocks.header }));
vi.mock("@/components/ChatSidebar", () => ({ ChatSidebar: () => null }));
vi.mock("@/components/ChatSessionList", () => ({ ChatSessionList: () => null }));
vi.mock("@/plugins", () => ({ PluginSlot: () => null }));
vi.mock("@/lib/api", () => ({
  HERMES_BASE_PATH: "",
  buildWsAuthParam: vi.fn(async () => ["token", "test"]),
  api: { getConfig: vi.fn(async () => ({})) },
}));
import ChatPage from "./ChatPage";

function ChatHarness() {
  return <MemoryRouter initialEntries={["/chat"]}>
    <Link to="/chat?learn=example">Seed learning</Link>
    <ChatPage />
  </MemoryRouter>;
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  delete window.__HERMES_SESSION_TOKEN__;
  mocks.terminals.length = 0;
  mocks.sockets.length = 0;
  mocks.theme.terminalBackground = "#000000";
});

describe("embedded PTY lifecycle", () => {
  it("keeps its terminal and socket through theme and query changes and consumes the latest learn seed", async () => {
    Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
    vi.useFakeTimers();
    window.__HERMES_SESSION_TOKEN__ = "test";
    vi.stubGlobal("requestAnimationFrame", vi.fn(() => 1));
    vi.stubGlobal("cancelAnimationFrame", vi.fn());
    vi.stubGlobal("ResizeObserver", class { observe = vi.fn(); disconnect = vi.fn(); });
    vi.stubGlobal("WebSocket", class {
      static OPEN = 1;
      readyState = 1;
      onopen: (() => void) | null = null;
      send = vi.fn();
      close = vi.fn();
      constructor() { mocks.sockets.push(this); }
    });
    vi.stubGlobal("matchMedia", vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
    window.matchMedia = globalThis.matchMedia;
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);
    try {
      await act(async () => root.render(<ChatHarness />));
      const terminal = mocks.terminals[0];
      const socket = mocks.sockets[0];
      expect(terminal).toBeDefined();
      expect(socket).toBeDefined();
      mocks.theme.terminalBackground = "#123456";
      await act(async () => root.render(<ChatHarness />));
      expect(terminal.options.theme).toMatchObject({ background: "#123456" });
      await act(async () => container.querySelector("a")!.click());
      await act(async () => socket.onopen!());
      await act(async () => vi.advanceTimersByTime(800));
      expect(socket.send).toHaveBeenCalledWith("/learn example\r");
      expect(mocks.terminals).toHaveLength(1);
      expect(mocks.sockets).toHaveLength(1);
      expect(terminal.dispose).not.toHaveBeenCalled();
      expect(socket.close).not.toHaveBeenCalled();
    } finally {
      await act(async () => root.unmount());
      container.remove();
    }
  });
});
