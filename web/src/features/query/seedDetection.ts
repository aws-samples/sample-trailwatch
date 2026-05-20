// Seed-type detection for the Investigate toolbar.
//
// The user pastes one fact (ARN / IP / access key / 12-digit account id /
// IAM user or role name) and the toolbar shows a chip indicating what type
// the app inferred. The user can override the chip via dropdown if the
// detection is wrong (e.g., a role name that happens to look like a user
// name). The detected type drives which scenario parameter slot the seed
// will eventually populate when run from the toolbar (PR 2 wiring).
//
// Heuristics, in detection order:
//   1. arn:aws:* prefix → ARN
//   2. AKIA / ASIA prefix + 16-20 alphanumerics → access key
//   3. Pure 12-digit number → AWS account ID
//   4. Looks like an IPv4 / IPv6 address → IP
//   5. Otherwise → "unknown" (UI prompts for explicit type)
//
// "user" vs "role" is ambiguous from a string alone (both are
// "[a-zA-Z0-9+=,.@_-]"); the UI defaults to "user" and lets the user
// override to "role" if needed.

export type SeedType = 'arn' | 'access_key' | 'ip' | 'account' | 'user' | 'role' | 'unknown'

const ARN_PREFIX = /^arn:aws:/i
const ACCESS_KEY = /^(AKIA|ASIA)[0-9A-Z]{12,20}$/
const ACCOUNT_ID = /^\d{12}$/
// Loose IPv4 + IPv6 sanity check; not full RFC validation but enough to
// distinguish IP addresses from other identifiers.
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6 = /^[0-9a-f:]+:[0-9a-f:]+$/i

export function detectSeedType(input: string): SeedType {
  const s = input.trim()
  if (!s) return 'unknown'
  if (ARN_PREFIX.test(s)) return 'arn'
  if (ACCESS_KEY.test(s)) return 'access_key'
  if (ACCOUNT_ID.test(s)) return 'account'
  if (IPV4.test(s) && validIPv4Octets(s)) return 'ip'
  if (IPV6.test(s)) return 'ip'
  // Strings that look like names default to "user"; users override to "role"
  // in the UI when needed.
  if (/^[A-Za-z0-9+=,.@_\-]+$/.test(s)) return 'user'
  return 'unknown'
}

function validIPv4Octets(s: string): boolean {
  const parts = s.split('.')
  if (parts.length !== 4) return false
  for (const p of parts) {
    const n = Number(p)
    if (!Number.isInteger(n) || n < 0 || n > 255) return false
  }
  return true
}

export function seedTypeLabel(t: SeedType): string {
  switch (t) {
    case 'arn': return 'ARN'
    case 'access_key': return 'access key'
    case 'ip': return 'IP'
    case 'account': return 'account ID'
    case 'user': return 'IAM user'
    case 'role': return 'IAM role'
    default: return 'unknown'
  }
}
