import { describe, expect, it } from 'vitest'
import { ORGANIZATION_TRAIL_MODE } from './S3ConfigView'

describe('organization trail mode wording', () => {
  it('uses inclusive UI copy without changing the API value', () => {
    expect(ORGANIZATION_TRAIL_MODE).toEqual({
      value: 'control_tower',
      label: 'Organization / Control Tower',
      description: 'Multi-account trail',
    })
  })
})
