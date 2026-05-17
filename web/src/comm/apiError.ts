// Shared helper for turning a non-2xx Response into a user-facing message.
// Backend returns { code, message, details? } per internal/render/render.go.
// This handles missing/malformed bodies without throwing further.

export interface ApiErrorBody {
  code?: string
  message?: string
  details?: unknown
}

export async function readApiError(res: Response, fallback = 'Request failed'): Promise<string> {
  // Drain body text first so we can recover from non-JSON responses (HTML 404s,
  // proxy errors, empty bodies). One-shot read — Response body can only be
  // consumed once.
  let text = ''
  try {
    text = await res.text()
  } catch {
    return `${fallback} (HTTP ${res.status})`
  }

  if (!text) return `${fallback} (HTTP ${res.status})`

  try {
    const body = JSON.parse(text) as ApiErrorBody
    if (body && typeof body.message === 'string' && body.message) return body.message
  } catch {
    // not JSON — fall through to text body
  }
  // Non-JSON: include first 200 chars of the body so the user can see what came back.
  const snippet = text.length > 200 ? `${text.slice(0, 200)}…` : text
  return `${fallback} (HTTP ${res.status}): ${snippet}`
}
