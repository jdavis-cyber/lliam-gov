// First-run provider selection screen (AI-329).
//
// Lets a new user choose among Claude Code / Codex / Gemini on a fresh machine.
// Shows each provider's readiness, the exact CLI install/login command for any
// that aren't ready, and a "Test" action that runs one real prompt through the
// chosen provider. No API-key field is ever rendered — the provider CLI owns
// auth (AI-334).
//
// Data contract + selection logic live in `@/lib/provider-selection` (unit
// tested). This component is presentational + fetch glue.

import { useCallback, useEffect, useState } from 'react'

import {
  defaultSelection,
  parseProviderCards,
  setupCommandFor,
  type CliProvidersResponse,
  type ProviderCard,
} from '@/lib/provider-selection'

const TONE_CLASS: Record<string, string> = {
  positive: 'text-emerald-400 border-emerald-700/50',
  warning: 'text-amber-400 border-amber-700/50',
  neutral: 'text-slate-300 border-slate-600/50',
  error: 'text-red-400 border-red-700/50',
}

interface TestState {
  status: 'idle' | 'running' | 'ok' | 'fail'
  detail?: string
}

export function FirstRunProviders() {
  const [cards, setCards] = useState<ProviderCard[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [tests, setTests] = useState<Record<string, TestState>>({})

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/providers/cli')
      if (!res.ok) {
        throw new Error(`provider status failed (${res.status})`)
      }
      const data = (await res.json()) as CliProvidersResponse
      const parsed = parseProviderCards(data)
      setCards(parsed)
      setSelectedId((prev) => prev ?? defaultSelection(parsed)?.id ?? null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load providers')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const runTest = useCallback(async (id: string) => {
    setTests((t) => ({ ...t, [id]: { status: 'running' } }))
    try {
      const res = await fetch(`/api/providers/cli/${id}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: 'Reply with exactly the single word: PROVIDER_OK' }),
      })
      const data = await res.json()
      if (data.ok) {
        setTests((t) => ({ ...t, [id]: { status: 'ok', detail: String(data.stdout ?? '').trim().slice(0, 120) } }))
      } else {
        const msg = data.error?.message ?? `exit ${data.exit_code}`
        setTests((t) => ({ ...t, [id]: { status: 'fail', detail: msg } }))
      }
    } catch (e) {
      setTests((t) => ({ ...t, [id]: { status: 'fail', detail: e instanceof Error ? e.message : 'error' } }))
    }
  }, [])

  if (loading) {
    return <div className="p-6 text-slate-400">Checking provider CLIs…</div>
  }

  return (
    <div className="mx-auto max-w-2xl p-6">
      <h1 className="text-xl font-semibold text-slate-100">Choose your AI provider</h1>
      <p className="mt-1 text-sm text-slate-400">
        Lliam-GOV runs inference through a provider&apos;s own CLI — no API keys. Pick one that&apos;s
        ready, or run the setup command to enable another. Switch any time.
      </p>

      {error && (
        <div className="mt-4 rounded border border-red-700/50 bg-red-950/30 p-3 text-sm text-red-300">
          {error}{' '}
          <button className="underline" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      <ul className="mt-5 space-y-3">
        {cards.map((card) => {
          const tone = TONE_CLASS[card.tone] ?? TONE_CLASS.neutral
          const setupCmd = setupCommandFor(card)
          const test = tests[card.id]
          const selected = selectedId === card.id
          return (
            <li
              key={card.id}
              className={`rounded-lg border p-4 ${selected ? 'border-sky-500 bg-sky-950/20' : 'border-slate-700 bg-slate-900/40'}`}
            >
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <input
                    type="radio"
                    name="provider"
                    checked={selected}
                    onChange={() => setSelectedId(card.id)}
                    aria-label={`Select ${card.display_name}`}
                  />
                  <div>
                    <div className="font-medium text-slate-100">{card.display_name}</div>
                    {card.default_model && (
                      <div className="text-xs text-slate-500">default model: {card.default_model}</div>
                    )}
                  </div>
                </div>
                <span className={`rounded border px-2 py-0.5 text-xs ${tone}`}>{card.status_label}</span>
              </div>

              {setupCmd && (
                <div className="mt-3">
                  <div className="text-xs text-slate-400">{card.action_label || 'Set up'}:</div>
                  <code className="mt-1 block rounded bg-slate-950 px-2 py-1 text-xs text-slate-200">{setupCmd}</code>
                </div>
              )}

              {card.selectable && (
                <div className="mt-3 flex items-center gap-3">
                  <button
                    className="rounded bg-sky-600 px-3 py-1 text-sm text-white hover:bg-sky-500 disabled:opacity-50"
                    disabled={test?.status === 'running'}
                    onClick={() => void runTest(card.id)}
                  >
                    {test?.status === 'running' ? 'Testing…' : 'Test'}
                  </button>
                  {test?.status === 'ok' && <span className="text-xs text-emerald-400">✓ {test.detail || 'works'}</span>}
                  {test?.status === 'fail' && <span className="text-xs text-red-400">✗ {test.detail}</span>}
                </div>
              )}
            </li>
          )
        })}
      </ul>

      <div className="mt-6 flex items-center gap-2">
        <button className="underline text-sm text-slate-400" onClick={() => void load()}>
          Refresh status
        </button>
      </div>
    </div>
  )
}

export default FirstRunProviders
