// Mirrors internal/config/config.go::S3Config
export interface S3Config {
  bucket: string
  region: string
  account_id: string
  mode: 'single' | 'control_tower'
  org_id?: string
  log_region?: string
  start_date?: string
  end_date?: string
  member_accounts?: string[]
}

// Mirrors internal/config/config.go::AuthConfig
export interface AuthConfig {
  method: 'imds' | 'session_credentials' | 'sso' | 'static'
  sso_profile?: string
  access_key_id?: string
  role_arn?: string
  external_id?: string
}

// Mirrors internal/config/config.go::BedrockConfig
export interface BedrockConfig {
  region: string
  model_id: string
  enabled: boolean
}

// Mirrors internal/config/config.go::LLMConfig. The settings handler
// (internal/features/settings/handler.go) substitutes the raw api_key with a
// has_key boolean when returning the config to the frontend.
export interface LLMConfig {
  provider: 'bedrock' | 'anthropic' | 'openai' | 'ollama'
  api_key?: string
  model?: string
  endpoint?: string
  max_session_spend_usd?: number
  has_key?: boolean
}

// Mirrors internal/config/config.go::Config
export interface AppConfig {
  port: number
  host?: string
  trusted_hosts?: string[]
  allow_auto_install?: boolean
  data_dir: string
  log_level: string
  query_timeout_seconds: number
  monitor_interval_seconds: number
  max_download_concurrency: number
  s3: S3Config
  auth: AuthConfig
  bedrock?: BedrockConfig
  llm?: LLMConfig
}

export interface CredentialStatus {
  source: string
  valid: boolean
  expires_at?: string
  error?: string
}
