import { describe, expect, it } from 'vitest'
import {
  detectSeedType,
  seedTypeForScenarioParam,
  seedTypeLabel,
  seedTypeMatchesScenarioParam,
} from './seedDetection'

describe('detectSeedType', () => {
  it.each([
    ['arn:aws:iam::123456789012:role/Example', 'arn'],
    ['AKIA1234567890ABCDEF', 'access_key'], // nosemgrep: detected-aws-access-key-id-value, aws-access-token
    ['123456789012', 'account'],
    ['192.0.2.10', 'ip'],
    ['2001:db8::1', 'ip'],
    ['incident-role', 'user'],
    ['', 'unknown'],
    ['999.2.3.4', 'unknown'],
  ] as const)('classifies %j as %s', (value, expected) => {
    expect(detectSeedType(value)).toBe(expected)
  })

  it('provides readable labels for explicit overrides', () => {
    expect(seedTypeLabel('role')).toBe('IAM role')
    expect(seedTypeLabel('unknown')).toBe('unknown')
  })

  it('maps ARN seeds to identity scenario parameters', () => {
    expect(seedTypeMatchesScenarioParam('arn', 'identity')).toBe(true)
    expect(seedTypeMatchesScenarioParam('arn', 'role')).toBe(false)
    expect(seedTypeForScenarioParam('identity')).toBe('arn')
  })

  it('does not expose unsupported scenario parameters as seed overrides', () => {
    expect(seedTypeForScenarioParam('none')).toBeNull()
    expect(seedTypeForScenarioParam('future_type')).toBeNull()
  })
})
