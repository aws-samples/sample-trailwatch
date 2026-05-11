export type SessionState =
  | 'pending'
  | 'downloading'
  | 'extracting'
  | 'verifying'
  | 'query-ready'
  | 'partially-verified'
  | 'failed'
  | 'interrupted'
  | 'deleted'

export interface Session {
  id: string
  bucket: string
  account_id: string
  org_id?: string
  region: string
  log_region: string
  mode: string
  start_date: string
  end_date: string
  state: SessionState
  total_files: number
  disk_usage_bytes: number
  failed_files?: string
  created_at: string
  updated_at: string
}

export interface ProcessingProgress {
  session_id: string
  phase: string
  files_completed: number
  total_files: number
  bytes_transferred: number
  total_bytes: number
  percentage: number
  estimated_eta_seconds: number
  message: string
}
