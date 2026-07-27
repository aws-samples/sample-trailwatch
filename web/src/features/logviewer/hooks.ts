import { useState, useEffect, useCallback, useRef } from 'react'
import { endpoints } from '../../config/api'
import type { Session, ProcessingProgress, IndexProgress, IndexStatusResponse } from '../../types/session'

interface CallerIdentity {
  account_id: string
  arn: string
  user_id: string
}

interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: string | null
}

export function useCallerIdentity() {
  const [state, setState] = useState<AsyncState<CallerIdentity>>({
    data: null,
    loading: true,
    error: null,
  })

  useEffect(() => {
    const fetchIdentity = async () => {
      setState({ data: null, loading: true, error: null })
      try {
        const res = await fetch(endpoints.callerIdentity)
        if (!res.ok) {
          const err = await res.json().catch(() => ({ message: 'Failed to fetch caller identity' }))
          throw new Error(err.message || `HTTP ${res.status}`)
        }
        const data: CallerIdentity = await res.json()
        setState({ data, loading: false, error: null })
      } catch (e) {
        setState({ data: null, loading: false, error: (e as Error).message })
      }
    }
    fetchIdentity()
  }, [])

  return state
}

interface CreateSessionRequest {
  account_id: string
  org_id?: string
  log_region: string
  start_date: string
  end_date: string
}

export function useCreateSession() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const createSession = useCallback(async (req: CreateSessionRequest): Promise<Session | null> => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(endpoints.sessions, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({ message: 'Failed to create session' }))
        throw new Error(data.message || `HTTP ${res.status}`)
      }
      const session: Session = await res.json()
      setLoading(false)
      return session
    } catch (e) {
      setError((e as Error).message)
      setLoading(false)
      return null
    }
  }, [])

  return { createSession, loading, error }
}

export function useSyncProgress(sessionId: string | null) {
  const [data, setData] = useState<ProcessingProgress | null>(null)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!sessionId) return

    setData(null)
    setDone(false)
    setError(null)

    const url = endpoints.sessionProgress(sessionId)
    const source = new EventSource(url)

    source.addEventListener('progress', (e) => {
      try {
        setData(JSON.parse((e as MessageEvent).data))
      } catch {
        // ignore parse errors
      }
    })

    source.addEventListener('done', () => {
      setDone(true)
      source.close()
    })

    source.addEventListener('error', (e) => {
      const errorEvent = e as MessageEvent
      if (errorEvent.data) {
        try {
          const parsed = JSON.parse(errorEvent.data)
          setError(parsed.message || 'Sync failed')
        } catch {
          setError('Sync failed')
        }
      }
      source.close()
    })

    source.onerror = () => {
      source.close()
    }

    return () => {
      source.close()
    }
  }, [sessionId])

  return { data, done, error }
}

export function useStartSync() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const startSync = useCallback(async (sessionId: string): Promise<boolean> => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(endpoints.sessionProcess(sessionId), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({ message: 'Failed to start sync' }))
        throw new Error(data.message || `HTTP ${res.status}`)
      }
      setLoading(false)
      return true
    } catch (e) {
      setError((e as Error).message)
      setLoading(false)
      return false
    }
  }, [])

  return { startSync, loading, error }
}

export function useSessions() {
  const [state, setState] = useState<AsyncState<Session[]>>({
    data: null,
    loading: true,
    error: null,
  })

  const fetchSessions = useCallback(async () => {
    setState(prev => ({ ...prev, loading: true, error: null }))
    try {
      const res = await fetch(endpoints.sessions)
      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: 'Failed to fetch sessions' }))
        throw new Error(err.message || `HTTP ${res.status}`)
      }
      const data = await res.json()
      const sessions: Session[] = Array.isArray(data) ? data : data.sessions || []
      setState({ data: sessions, loading: false, error: null })
    } catch (e) {
      setState({ data: null, loading: false, error: (e as Error).message })
    }
  }, [])

  useEffect(() => {
    fetchSessions()
  }, [fetchSessions])

  return { ...state, refetch: fetchSessions }
}

export function useDeleteSession() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const deleteSession = useCallback(async (sessionId: string): Promise<boolean> => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(endpoints.session(sessionId), {
        method: 'DELETE',
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({ message: 'Failed to delete session' }))
        throw new Error(data.message || `HTTP ${res.status}`)
      }
      setLoading(false)
      return true
    } catch (e) {
      setError((e as Error).message)
      setLoading(false)
      return false
    }
  }, [])

  return { deleteSession, loading, error }
}

export function useIndexStatus() {
  const [status, setStatus] = useState<IndexStatusResponse | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const res = await fetch(endpoints.indexStatus)
      if (res.ok) setStatus(await res.json())
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  return { status, loading, refresh }
}

// Reconnect backoff for the index-progress SSE stream. A long index build can
// keep the connection open for minutes and the browser/proxy may drop it; we
// reconnect with exponential backoff (capped) instead of hammering the endpoint
// in a tight loop. Backoff resets to the floor after a successful message.
const INDEX_SSE_BACKOFF_MIN_MS = 1000
const INDEX_SSE_BACKOFF_MAX_MS = 15000

export function useIndexProgress() {
  const [data, setData] = useState<IndexProgress | null>(null)
  const [done, setDone] = useState(false)
  const [active, setActive] = useState(false)
  const sourceRef = useRef<EventSource | null>(null)
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const backoffRef = useRef(INDEX_SSE_BACKOFF_MIN_MS)
  // Set once the consumer wants a live stream; cleared on disconnect/done so a
  // dropped connection only reconnects while a build is genuinely in progress.
  const wantStreamRef = useRef(false)
  const openStreamRef = useRef<() => void>(() => {})

  const clearRetry = useCallback(() => {
    if (retryTimerRef.current) {
      clearTimeout(retryTimerRef.current)
      retryTimerRef.current = null
    }
  }, [])

  const disconnect = useCallback(() => {
    wantStreamRef.current = false
    clearRetry()
    backoffRef.current = INDEX_SSE_BACKOFF_MIN_MS
    if (sourceRef.current) {
      sourceRef.current.close()
      sourceRef.current = null
    }
    setActive(false)
  }, [clearRetry])

  const openStream = useCallback(() => {
    // Tear down any prior connection/timer before opening a new one.
    clearRetry()
    if (sourceRef.current) {
      sourceRef.current.close()
      sourceRef.current = null
    }
    setActive(true)

    const source = new EventSource(endpoints.indexProgress)
    sourceRef.current = source

    source.addEventListener('progress', (e) => {
      // A successful message means the stream is healthy again — reset backoff.
      backoffRef.current = INDEX_SSE_BACKOFF_MIN_MS
      try {
        setData(JSON.parse((e as MessageEvent).data))
      } catch { /* ignore */ }
    })

    source.addEventListener('done', () => {
      wantStreamRef.current = false
      clearRetry()
      backoffRef.current = INDEX_SSE_BACKOFF_MIN_MS
      setDone(true)
      setActive(false)
      source.close()
      sourceRef.current = null
    })

    source.onerror = () => {
      source.close()
      sourceRef.current = null
      setActive(false)
      // Only reconnect if the consumer still wants the stream (build ongoing)
      // and we have not already scheduled a retry.
      if (!wantStreamRef.current || retryTimerRef.current) return
      const delay = backoffRef.current
      backoffRef.current = Math.min(delay * 2, INDEX_SSE_BACKOFF_MAX_MS)
      retryTimerRef.current = setTimeout(() => {
        retryTimerRef.current = null
        if (wantStreamRef.current) openStreamRef.current()
      }, delay)
    }
  }, [clearRetry])

  // Keep a stable ref to the latest openStream so the backoff timer can call it
  // without capturing a stale closure.
  openStreamRef.current = openStream

  const connect = useCallback(() => {
    wantStreamRef.current = true
    clearRetry()
    backoffRef.current = INDEX_SSE_BACKOFF_MIN_MS
    setData(null)
    setDone(false)
    openStream()
  }, [clearRetry, openStream])

  useEffect(() => {
    return () => { disconnect() }
  }, [disconnect])

  return { data, done, active, connect, disconnect }
}
