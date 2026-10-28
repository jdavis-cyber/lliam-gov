import {
  useCallback,
  useEffect,
  useEffectEvent,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useLocation, useSearchParams } from "react-router-dom";
import { api, setManagementProfile } from "@/lib/api";
import { ProfileContext } from "@/contexts/profile-context";

/**
 * Machine-level management-profile scope.
 *
 * One switcher (rendered in the sidebar) decides which profile every
 * management page reads/writes. React STATE is the source of truth; the
 * URL (`?profile=<name>`) is a synchronized projection of it so deep links
 * land scoped and refresh survives. The selection is mirrored into the api
 * module so `fetchJSON` transparently appends it to the profile-scoped
 * endpoint families. "" = the dashboard's own profile.
 *
 * Why state-first instead of URL-first: sidebar nav links are bare paths
 * (`/config`, `/skills`). A URL-derived scope would silently reset to the
 * dashboard's own profile on every nav click — the switcher would LOOK
 * global while normal navigation dropped the write target. With state as
 * truth, the effect below re-asserts `?profile=` onto the new location
 * after each navigation, so the scope survives nav and stays deep-linkable.
 *
 * This exists because "Set as active" on the Profiles page historically only
 * flipped the sticky active_profile file (future CLI/gateway runs). The
 * switcher is the dashboard's write-target selector for Chat and management
 * pages. We now sync the switcher when the sticky active profile differs from
 * the dashboard process on load, and ProfilesPage updates the switcher when
 * you click "Set as active".
 */
export function ProfileProvider({ children }: { children: ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const { pathname } = useLocation();
  const [profiles, setProfiles] = useState<string[]>([]);
  const [currentProfile, setCurrentProfile] = useState("default");

  // Initial value comes from the URL (deep link / refresh / unified-launch
  // preselect); afterwards state leads and the URL follows.
  const [profile, setProfileState] = useState(
    () => searchParams.get("profile") ?? "",
  );

  // Mirror into the api module synchronously on every render where it
  // changed, so fetches fired by child effects in the same commit see it.
  setManagementProfile(profile);

  // A profile param arriving via in-app navigation (e.g. the Profiles
  // page's "Manage skills & tools" linking to /skills?profile=X) must win
  // over current state — it's an explicit scope request.
  const urlProfile = searchParams.get("profile");
  const [previousUrlProfile, setPreviousUrlProfile] = useState(urlProfile);
  const [hasExplicitProfile, setHasExplicitProfile] = useState(urlProfile !== null);
  if (urlProfile !== previousUrlProfile) {
    setPreviousUrlProfile(urlProfile);
    if (urlProfile !== null) {
      setHasExplicitProfile(true);
      if (urlProfile !== profile) setProfileState(urlProfile);
    }
  }

  // Re-assert ?profile= after navigations that dropped it (bare nav links).
  // Runs on every pathname/profile change; no-ops when already in sync.
  useEffect(() => {
    const inUrl = searchParams.get("profile") ?? "";
    if ((profile || "") === inUrl) return;
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (profile) next.set("profile", profile);
        else next.delete("profile");
        return next;
      },
      { replace: true },
    );
  }, [pathname, profile, searchParams, setSearchParams]);

  // Consult the committed selection when discovery completes, so a slow
  // initial request cannot overwrite a profile explicitly selected meanwhile.
  const alignInitialProfile = useEffectEvent((current: string, active: string) => {
    if (!hasExplicitProfile && urlProfile === null && active !== current) {
      setManagementProfile(active);
      setProfileState(active);
    }
  });

  useEffect(() => {
    let cancelled = false;

    Promise.all([api.getProfiles(), api.getActiveProfile()])
      .then(([profilesRes, info]) => {
        if (cancelled) return;

        setProfiles(profilesRes.profiles.map((p) => p.name));

        const current = info.current || "default";
        const active = info.active || "default";
        setCurrentProfile(current);

        alignInitialProfile(current, active);
      })
      .catch(() => {});

    return () => {
      cancelled = true;
    };
  }, []);

  const setProfile = useCallback(
    (name: string) => {
      setHasExplicitProfile(true);
      setManagementProfile(name);
      setProfileState(name);
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (name) next.set("profile", name);
          else next.delete("profile");
          return next;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  const value = useMemo(
    () => ({ profile, currentProfile, profiles, setProfile }),
    [profile, currentProfile, profiles, setProfile],
  );

  return (
    <ProfileContext.Provider value={value}>{children}</ProfileContext.Provider>
  );
}
