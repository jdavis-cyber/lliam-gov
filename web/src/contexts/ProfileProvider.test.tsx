// @vitest-environment jsdom
import { act, useContext, useEffect } from "react";
import { createRoot, type Root } from "react-dom/client";
import { Link, MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ProfileProvider } from "./ProfileProvider";
import { ProfileContext } from "./profile-context";
import { api, setManagementProfile } from "@/lib/api";

function ScopeProbe() {
  const { profile } = useContext(ProfileContext);
  const location = useLocation();
  useEffect(() => { void api.getConfig(); }, [profile, location.pathname]);
  return <>
    <output>{profile}|{location.pathname}|{location.search}</output>
    <Link to="/skills">Bare navigation</Link>
    <Link to="/config?profile=beta">Explicit profile</Link>
  </>;
}

let root: Root;
let container: HTMLDivElement;
const fetchDefault = async (input: RequestInfo | URL) => {
  const url = String(input);
  const payload = url.includes("/api/profiles/active")
    ? { current: "default", active: "default" }
    : url.includes("/api/profiles") ? { profiles: [] } : {};
  return new Response(JSON.stringify(payload), { headers: { "content-type": "application/json" } });
};
const fetchMock = vi.fn(fetchDefault);
beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  fetchMock.mockReset().mockImplementation(fetchDefault);
  vi.stubGlobal("fetch", fetchMock);
  setManagementProfile("");
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
  setManagementProfile("");
  vi.unstubAllGlobals();
});

describe("management profile navigation", () => {
  it("retains scope across bare navigation and applies explicit scope before child fetch effects", async () => {
    await act(async () => root.render(
      <MemoryRouter initialEntries={["/config?profile=alpha"]}>
        <ProfileProvider><ScopeProbe /></ProfileProvider>
      </MemoryRouter>,
    ));
    expect(container.querySelector("output")?.textContent).toContain("alpha|/config|?profile=alpha");
    fetchMock.mockClear();
    await act(async () => container.querySelectorAll("a")[0].click());
    expect(container.querySelector("output")?.textContent).toContain("alpha|/skills|?profile=alpha");
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("/api/config?profile=alpha"))).toBe(true);
    fetchMock.mockClear();
    await act(async () => container.querySelectorAll("a")[1].click());
    expect(container.querySelector("output")?.textContent).toContain("beta|/config|?profile=beta");
    const configRequests = fetchMock.mock.calls.filter(([url]) => String(url).includes("/api/config"));
    expect(configRequests.length).toBeGreaterThan(0);
    expect(configRequests.every(([url]) => String(url).includes("profile=beta"))).toBe(true);
  });

  it("does not overwrite explicit navigation when initial active-profile discovery resolves late", async () => {
    let resolveActive!: (response: Response) => void;
    const activeResponse = new Promise<Response>((resolve) => { resolveActive = resolve; });
    fetchMock.mockImplementation(async (input) => String(input).includes("/api/profiles/active")
      ? activeResponse : fetchDefault(input));
    await act(async () => root.render(
      <MemoryRouter initialEntries={["/config"]}>
        <ProfileProvider><ScopeProbe /></ProfileProvider>
      </MemoryRouter>,
    ));
    await act(async () => container.querySelectorAll("a")[1].click());
    expect(container.querySelector("output")?.textContent).toContain("beta|/config|?profile=beta");
    fetchMock.mockClear();
    await act(async () => resolveActive(new Response(JSON.stringify({ current: "default", active: "old-active" }))));
    expect(container.querySelector("output")?.textContent).toContain("beta|/config|?profile=beta");
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes("profile=old-active"))).toBe(false);
  });
});
