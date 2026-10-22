// @vitest-environment jsdom
import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PluginPage } from "./PluginPage";
import { exposePluginSDK, notifyPluginRegistry, setPluginLoadError } from "./registry";

function CounterPlugin() {
  const [count, setCount] = useState(0);
  return <button onClick={() => setCount((previous) => previous + 1)}>{count}</button>;
}

let container: HTMLDivElement;
let root: Root;
beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  exposePluginSDK();
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

describe("dynamic plugin lifecycle", () => {
  it("renders a pre-registered plugin and preserves its state across registry notifications", async () => {
    window.__HERMES_PLUGINS__!.register("counter-existing", CounterPlugin);
    await act(async () => root.render(<PluginPage name="counter-existing" />));
    await act(async () => container.querySelector("button")!.click());
    expect(container.textContent).toBe("1");
    await act(async () => notifyPluginRegistry());
    await act(async () => root.render(<PluginPage name="counter-existing" />));
    expect(container.textContent).toBe("1");
  });

  it("transitions from loading or load error to a plugin registered after mount", async () => {
    await act(async () => root.render(<PluginPage name="counter-late" />));
    expect(container.querySelector("button")).toBeNull();
    await act(async () => setPluginLoadError("counter-late", "LOAD_FAILED"));
    expect(container.querySelector('[role="alert"]')).not.toBeNull();
    await act(async () => window.__HERMES_PLUGINS__!.register("counter-late", CounterPlugin));
    expect(container.querySelector('[role="alert"]')).toBeNull();
    expect(container.querySelector("button")?.textContent).toBe("0");
  });
});
