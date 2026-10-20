import { act, cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

// JSDOM omits CSS.escape, which Chromium provides for timeline and cron selectors.
// Serialize an identifier using the CSSOM escaping rules, including control
// characters, leading digits, a lone hyphen, and non-ASCII message IDs.
function escapeIdentifier(value: string): string {
  const text = String(value)
  let escaped = ''

  for (let index = 0; index < text.length; index++) {
    const code = text.charCodeAt(index)

    if (code === 0) {
      escaped += '\uFFFD'
    } else if (
      (code >= 1 && code <= 31) ||
      code === 127 ||
      (index === 0 && code >= 48 && code <= 57) ||
      (index === 1 && code >= 48 && code <= 57 && text.charCodeAt(0) === 45)
    ) {
      escaped += `\\${code.toString(16)} `
    } else if (index === 0 && code === 45 && text.length === 1) {
      escaped += '\\-'
    } else if (
      code >= 128 ||
      code === 45 ||
      code === 95 ||
      (code >= 48 && code <= 57) ||
      (code >= 65 && code <= 90) ||
      (code >= 97 && code <= 122)
    ) {
      escaped += text[index]
    } else {
      escaped += `\\${text[index]}`
    }
  }

  return escaped
}

if (!globalThis.CSS?.escape) {
  Object.defineProperty(globalThis, 'CSS', {
    configurable: true,
    value: { ...globalThis.CSS, escape: escapeIdentifier }
  })
}

// Vitest uses explicit imports, so Testing Library's global afterEach detection
// is unavailable. Unmount every React root and flush its pending cleanup before
// the worker disposes window (including React scheduler work queued by effects).
afterEach(async () => {
  cleanup()
  await act(async () => {})
})
