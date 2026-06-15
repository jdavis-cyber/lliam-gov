// First-run provider selection logic (AI-329).
//
// Framework-agnostic mapping over the GET /api/providers/cli payload, so the
// first-run screen and model picker can render Claude Code / Codex / Gemini as
// selectable cards with exact CLI setup commands — never an API-key prompt
// (AI-334: the provider CLI owns auth).

export type ProviderCardState =
  | 'ready'
  | 'not_installed'
  | 'not_authenticated'
  | 'degraded'
  | 'unavailable'

export interface ProviderCard {
  id: string
  display_name: string
  state: ProviderCardState
  status_label: string
  tone: string
  selectable: boolean
  action_label: string
  action_command: string
  default_model: string | null
}

export interface CliProviderEntry {
  id: string
  readiness: string
  card: ProviderCard
}

export interface CliProvidersResponse {
  providers: CliProviderEntry[]
}

/** Extract the render-ready cards from the API payload (defensive on shape). */
export function parseProviderCards(resp: CliProvidersResponse | null | undefined): ProviderCard[] {
  if (!resp || !Array.isArray(resp.providers)) {
    return []
  }
  return resp.providers
    .map((entry) => entry?.card)
    .filter((card): card is ProviderCard => Boolean(card && card.id))
}

/** Providers the user can actually pick right now. */
export function readyProviders(cards: ProviderCard[]): ProviderCard[] {
  return cards.filter((c) => c.selectable)
}

/**
 * Default first-run highlight: the first ready provider, else the first card so
 * the screen always has a focused option to guide setup.
 */
export function defaultSelection(cards: ProviderCard[]): ProviderCard | null {
  if (cards.length === 0) {
    return null
  }
  return readyProviders(cards)[0] ?? cards[0]
}

/** The exact CLI command to make a provider ready, or null if already ready. */
export function setupCommandFor(card: ProviderCard): string | null {
  if (card.selectable || !card.action_command) {
    return null
  }
  return card.action_command
}

/**
 * AI-334 invariant for the UI: a provider card never asks for an API key — its
 * only action is a CLI command (or none). Used to assert no key-entry field is
 * rendered for CLI-backed providers.
 */
export function requiresApiKey(_card: ProviderCard): boolean {
  return false
}
