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

export interface ProgressSnapshot extends ProcessingProgress {
  started_at: string
  last_updated_at: string
  speed_bytes_per_sec: number
  files_per_sec: number
  eta_seconds: number
  concurrency: number
}

export type IndexStatus = 'idle' | 'building' | 'paused' | 'error'

export interface IndexProgress {
  status: string
  total_bytes: number
  processed_bytes: number
  total_files: number
  processed_files: number
  percentage: number
  current_batch: number
  total_batches: number
  message: string
}

export interface IndexStatusResponse {
  indexed: boolean
  age_seconds?: number
  size_bytes?: number
  index_status?: IndexStatus
  total_files_indexed?: number
  total_bytes_indexed?: number
  started_at?: string
}
