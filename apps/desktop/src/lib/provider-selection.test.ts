// Tests for first-run provider selection logic (AI-329).
//
// Vitest style to match the rest of the desktop suite. The same assertions were
// also verified independently with Node's built-in test runner during
// development (the module is dependency-free).

import { describe, expect, it } from 'vitest'

import {
  parseProviderCards,
  readyProviders,
  defaultSelection,
  setupCommandFor,
  requiresApiKey,
  type ProviderCard,
  type CliProvidersResponse,
} from './provider-selection'

function card(over: Partial<ProviderCard>): ProviderCard {
  return {
    id: 'claude-code',
    display_name: 'Claude Code CLI',
    state: 'ready',
    status_label: 'Ready',
    tone: 'positive',
    selectable: true,
    action_label: '',
    action_command: '',
    default_model: 'sonnet',
    ...over,
  }
}

const RESP: CliProvidersResponse = {
  providers: [
    {
      id: 'claude-code',
      readiness: 'not_authenticated',
      card: card({
        id: 'claude-code',
        state: 'not_authenticated',
        selectable: false,
        action_label: 'Sign in',
        action_command: 'claude setup-token',
      }),
    },
    {
      id: 'codex',
      readiness: 'ready',
      card: card({ id: 'codex', display_name: 'Codex CLI', state: 'ready', selectable: true }),
    },
    {
      id: 'gemini',
      readiness: 'not_installed',
      card: card({
        id: 'gemini',
        display_name: 'Gemini CLI',
        state: 'not_installed',
        selectable: false,
        action_label: 'Install',
        action_command: 'npm install -g @google/gemini-cli',
      }),
    },
  ],
}

describe('provider-selection', () => {
  it('parses all three cards', () => {
    const cards = parseProviderCards(RESP)
    expect(cards.map((c) => c.id)).toEqual(['claude-code', 'codex', 'gemini'])
  })

  it('is defensive on bad shapes', () => {
    expect(parseProviderCards(null)).toEqual([])
    expect(parseProviderCards({ providers: [] })).toEqual([])
    // @ts-expect-error intentionally malformed
    expect(parseProviderCards({ providers: [{ id: 'x' }] })).toEqual([])
  })

  it('returns only selectable as ready', () => {
    expect(readyProviders(parseProviderCards(RESP)).map((c) => c.id)).toEqual(['codex'])
  })

  it('defaults to a ready provider', () => {
    expect(defaultSelection(parseProviderCards(RESP))?.id).toBe('codex')
  })

  it('defaults to the first card when none ready', () => {
    const noneReady = parseProviderCards(RESP).map((c) => ({ ...c, selectable: false }))
    expect(defaultSelection(noneReady)?.id).toBe('claude-code')
  })

  it('exposes the CLI setup command for unready providers only', () => {
    const cards = parseProviderCards(RESP)
    expect(setupCommandFor(cards[0])).toBe('claude setup-token')
    expect(setupCommandFor(cards[1])).toBeNull()
    expect(setupCommandFor(cards[2])).toBe('npm install -g @google/gemini-cli')
  })

  it('never requires an API key (AI-334)', () => {
    for (const c of parseProviderCards(RESP)) {
      expect(requiresApiKey(c)).toBe(false)
    }
  })
})
