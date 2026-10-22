// One-time localStorage key migration for the hermes -> lliam-gov rename.
//
// The desktop persists user state (composer drafts, toast snoozes, theme/skin
// choices, onboarding flags, pane layout, pet position, ...) under keys that
// used to be prefixed `hermes*`. Renaming the product renamed the keys, which
// would otherwise orphan every user's persisted state on first launch of the
// renamed build.
//
// D2 copy-don't-move: for each old key present whose new-prefixed key is
// absent, copy the value across. The old key is intentionally LEFT in place —
// copying (not moving) means a user who downgrades to a pre-rename build still
// finds their state, and a partially-migrated store can't lose data. The guard
// (`new key absent`) makes this idempotent: once the new key exists, later runs
// are no-ops and never clobber newer writes.
//
// Prefix families (must stay in sync with the key literals across store/,
// themes/, components/, app/):
//   hermes:              -> lliam-gov:            (toast snoozes, drafts, notifs)
//   hermes.desktop.      -> lliam-gov.desktop.    (the bulk of persisted atoms)
//   hermes-desktop-      -> lliam-gov-desktop-    (theme/skin/profile/onboarded)
//   hermes-onboarding-   -> lliam-gov-onboarding- (onboarding skip/show-all)
//   hermes-boot-         -> lliam-gov-boot-       (first-paint bg/color-scheme)
const PREFIX_MAP: ReadonlyArray<readonly [string, string]> = [
  ['hermes:', 'lliam-gov:'],
  ['hermes.desktop.', 'lliam-gov.desktop.'],
  ['hermes-desktop-', 'lliam-gov-desktop-'],
  ['hermes-onboarding-', 'lliam-gov-onboarding-'],
  ['hermes-boot-', 'lliam-gov-boot-']
]

function newKeyFor(oldKey: string): string | null {
  for (const [oldPrefix, newPrefix] of PREFIX_MAP) {
    if (oldKey.startsWith(oldPrefix)) {
      return newPrefix + oldKey.slice(oldPrefix.length)
    }
  }

  return null
}

/**
 * Copy any legacy `hermes*` localStorage keys onto their `lliam-gov*`
 * equivalents. Idempotent and safe to call on every startup; runs before any
 * store module reads a key so migrated state is visible on first render.
 */
export function migrateLegacyStorageKeys(storage: Storage = window.localStorage): void {
  try {
    // Snapshot keys first — we write during iteration, and mutating a live
    // Storage while walking it by index is undefined behaviour across engines.
    const oldKeys: string[] = []

    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i)

      if (key && newKeyFor(key)) {
        oldKeys.push(key)
      }
    }

    for (const oldKey of oldKeys) {
      const newKey = newKeyFor(oldKey)

      if (!newKey) {
        continue
      }

      // Copy only when the new key is absent — never clobber a value the
      // renamed build has already written.
      if (storage.getItem(newKey) !== null) {
        continue
      }

      const value = storage.getItem(oldKey)

      if (value !== null) {
        storage.setItem(newKey, value)
      }
    }
  } catch {
    // localStorage can throw (private mode / quota / disabled). A failed
    // migration must never block app boot — worst case the user re-does
    // onboarding, which is recoverable.
  }
}
