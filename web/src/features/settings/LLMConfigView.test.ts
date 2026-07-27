import { describe, expect, it } from 'vitest'
import {
  BEDROCK_REGIONS,
  DEFAULT_BEDROCK_MODEL_ID,
  defaultModel,
  isAnthropicBedrockModel,
  type BedrockModel,
} from './LLMConfigView'

function model(provider: string): BedrockModel {
  return {
    model_id: `${provider.toLowerCase()}.example`,
    model_name: `${provider} example`,
    provider,
    input_modes: ['TEXT'],
    output_modes: ['TEXT'],
    is_cris: false,
  }
}

describe('Bedrock configuration', () => {
  it('uses the active Sonnet default', () => {
    expect(DEFAULT_BEDROCK_MODEL_ID).toBe('us.anthropic.claude-sonnet-4-6')
    expect(defaultModel('bedrock')).toBe(DEFAULT_BEDROCK_MODEL_ID)
  })

  it('includes the Ohio region for persisted configurations', () => {
    expect(BEDROCK_REGIONS).toContainEqual({
      value: 'us-east-2',
      label: 'US East (Ohio)',
    })
  })

  it('only accepts models compatible with the provider request schema', () => {
    expect(isAnthropicBedrockModel(model('Anthropic'))).toBe(true)
    expect(isAnthropicBedrockModel(model('Amazon'))).toBe(false)
    expect(isAnthropicBedrockModel(model('Meta'))).toBe(false)
  })
})
