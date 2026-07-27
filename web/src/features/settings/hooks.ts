import { useState, useEffect, useCallback, useRef } from 'react'
import { endpoints } from '../../config/api'
import type { AppConfig } from '../../types/config'

interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: string | null
}

export function useSettings() {
  const [state, setState] = useState<AsyncState<AppConfig>>({
    data: null,
    loading: true,
    error: null,
  })
  const requestIdRef = useRef(0)
  const controllerRef = useRef<AbortController | null>(null)

  const fetchSettings = useCallback(async () => {
    controllerRef.current?.abort()
    const requestId = ++requestIdRef.current
    const controller = new AbortController()
    controllerRef.current = controller

    setState(prev => ({ ...prev, loading: true, error: null }))
    try {
      const res = await fetch(endpoints.settings, { signal: controller.signal })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: 'Failed to fetch settings' }))
        throw new Error(err.message || `HTTP ${res.status}`)
      }
      const data: AppConfig = await res.json()
      if (requestId === requestIdRef.current) {
        setState({ data, loading: false, error: null })
      }
    } catch (e) {
      if (controller.signal.aborted || requestId !== requestIdRef.current) return
      setState({ data: null, loading: false, error: (e as Error).message })
    } finally {
      if (controllerRef.current === controller) {
        controllerRef.current = null
      }
    }
  }, [])

  useEffect(() => {
    void fetchSettings()
    return () => {
      requestIdRef.current += 1
      controllerRef.current?.abort()
      controllerRef.current = null
    }
  }, [fetchSettings])

  return { ...state, refetch: fetchSettings }
}

interface HealthCheck {
  name: string
  status: 'ok' | 'error' | 'unconfigured'
  message: string
}

interface HealthResponse {
  version: string
  uptime: string
  checks: HealthCheck[]
}

export function useHealth() {
  const [state, setState] = useState<AsyncState<HealthResponse>>({
    data: null,
    loading: true,
    error: null,
  })

  const fetchHealth = useCallback(async () => {
    setState(prev => ({ ...prev, loading: true, error: null }))
    try {
      const res = await fetch(endpoints.health)
      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: 'Failed to fetch health' }))
        throw new Error(err.message || `HTTP ${res.status}`)
      }
      const data: HealthResponse = await res.json()
      setState({ data, loading: false, error: null })
    } catch (e) {
      setState({ data: null, loading: false, error: (e as Error).message })
    }
  }, [])

  useEffect(() => {
    fetchHealth()
  }, [fetchHealth])

  return { ...state, refetch: fetchHealth }
}

export type { HealthCheck, HealthResponse }
