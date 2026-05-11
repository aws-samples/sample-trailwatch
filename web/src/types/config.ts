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

export interface AuthConfig {
  method: 'imds' | 'session_credentials' | 'sso' | 'static'
  sso_profile?: string
  access_key_id?: string
}

export interface AppConfig {
  port: number
  data_dir: string
  log_level: string
  query_timeout_seconds: number
  monitor_interval_seconds: number
  max_download_concurrency: number
  s3: S3Config
  auth: AuthConfig
}

export interface CredentialStatus {
  source: string
  valid: boolean
  expires_at?: string
  error?: string
}
