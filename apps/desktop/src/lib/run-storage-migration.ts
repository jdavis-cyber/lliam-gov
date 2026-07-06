// Side-effect entry: runs the legacy localStorage key migration exactly once,
// at import time. main.tsx imports this FIRST so it executes before any other
// store module's import-time key reads.
//
// Why a dedicated side-effect module instead of calling the function inline in
// main.tsx: ES `import` statements are hoisted and run before any executable
// statement in the module body, so a plain `migrateLegacyStorageKeys()` call in
// main.tsx would run AFTER every `import './store/...'` side effect. Ordering
// the migration ahead of those reads requires it to itself be the first import.
import { migrateLegacyStorageKeys } from './migrate-storage-keys'

migrateLegacyStorageKeys()
