import { useState, useEffect, useCallback } from 'react'
import { endpoints } from '../../config/api'
import type { Session, ProcessingProgress } from '../../types/session'

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
  bucket: string
  account_id: string
  org_id?: string
  region: string
  log_region: string
  mode: string
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
