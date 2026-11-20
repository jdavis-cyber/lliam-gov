import type { ApprovalRespondResponse } from '../gatewayTypes.js'
import type { ApprovalReq } from '../types.js'

import type { GatewayRpc } from './interfaces.js'
import { getOverlayState, patchOverlayState } from './overlayStore.js'
import { patchTurnState } from './turnStore.js'
import { getUiState, patchUiState } from './uiStore.js'

export function createApprovalResponder(rpc: GatewayRpc) {
  const pending = new WeakSet<ApprovalReq>()

  return async (choice: string, request: ApprovalReq) => {
    const sessionId = request.sessionId ?? getUiState().sid
    const isCurrent = () => getOverlayState().approval === request && getUiState().sid === sessionId

    if (!isCurrent() || pending.has(request)) {
      return
    }

    pending.add(request)

    try {
      const response = await rpc<ApprovalRespondResponse>('approval.respond', {
        choice,
        ...(request.requestId && { request_id: request.requestId }),
        session_id: sessionId
      })

      // A timeout or another window can resolve the request while the RPC is in flight.
      if (!response || !isCurrent()) {
        return
      }

      if (response.resolved === 0) {
        patchOverlayState({ approval: null })
        patchUiState({ status: 'approval expired or already answered' })

        return
      }

      const acknowledged =
        response.resolved === undefined
          ? !request.requestId && response.ok === true
          : Number.isInteger(response.resolved) && response.resolved > 0

      if (!acknowledged) {
        patchUiState({ status: 'approval was not acknowledged' })

        return
      }

      patchOverlayState({ approval: null })
      patchTurnState({ outcome: choice === 'deny' ? 'denied' : `approved (${choice})` })
      patchUiState({ status: 'running…' })
    } finally {
      pending.delete(request)
    }
  }
}
