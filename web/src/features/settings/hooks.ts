import { useState, useEffect, useCallback } from 'react'
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

  const fetchSettings = useCallback(async () => {
    setState(prev => ({ ...prev, loading: true, error: null }))
    try {
      const res = await fetch(endpoints.settings)
      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: 'Failed to fetch settings' }))
        throw new Error(err.message || `HTTP ${res.status}`)
      }
      const data: AppConfig = await res.json()
      setState({ data, loading: false, error: null })
    } catch (e) {
      setState({ data: null, loading: false, error: (e as Error).message })
    }
  }, [])

  useEffect(() => {
    fetchSettings()
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
