import { useState, useEffect, useCallback } from 'react'
import { endpoints } from '../../config/api'
import type { AppConfig } from '../../types/config'

interface ValidationResult {
  valid: boolean
  message: string
  accounts?: string[]
}

interface CredentialAttempt {
  source: string
  success: boolean
  reason?: string
}

interface CredentialValidationResult {
  source: string
  valid: boolean
  message: string
  attempts: CredentialAttempt[]
}

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

export function useValidation() {
  const [bucketState, setBucketState] = useState<AsyncState<ValidationResult>>({
    data: null,
    loading: false,
    error: null,
  })

  const [credentialState, setCredentialState] = useState<AsyncState<CredentialValidationResult>>({
    data: null,
    loading: false,
    error: null,
  })

  const validateBucket = useCallback(async (bucket: string, region: string) => {
    setBucketState({ data: null, loading: true, error: null })
    try {
      const res = await fetch(endpoints.validateBucket, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bucket, region }, ['bucket', 'region']),
      })
      const data = await res.json()
      if (!res.ok) {
        setBucketState({ data: null, loading: false, error: data.message || `HTTP ${res.status}` })
        return null
      }
      setBucketState({ data, loading: false, error: null })
      return data as ValidationResult
    } catch (e) {
      setBucketState({ data: null, loading: false, error: (e as Error).message })
      return null
    }
  }, [])

  const validateCredentials = useCallback(async () => {
    setCredentialState({ data: null, loading: true, error: null })
    try {
      const res = await fetch(endpoints.validateCredentials, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      const data = await res.json()
      if (!res.ok) {
        setCredentialState({ data: null, loading: false, error: data.message || `HTTP ${res.status}` })
        return null
      }
      setCredentialState({ data, loading: false, error: null })
      return data as CredentialValidationResult
    } catch (e) {
      setCredentialState({ data: null, loading: false, error: (e as Error).message })
      return null
    }
  }, [])

  return {
    bucket: bucketState,
    credentials: credentialState,
    validateBucket,
    validateCredentials,
  }
}

export function useSaveSettings() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState(false)

  const save = useCallback(async (config: Partial<AppConfig>) => {
    setLoading(true)
    setError(null)
    setSuccess(false)
    try {
      const res = await fetch(endpoints.settings, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config, Object.keys(config).sort()),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({ message: 'Failed to save settings' }))
        throw new Error(data.message || `HTTP ${res.status}`)
      }
      setSuccess(true)
      setLoading(false)
      return true
    } catch (e) {
      setError((e as Error).message)
      setLoading(false)
      return false
    }
  }, [])

  return { save, loading, error, success }
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

export function useAccounts() {
  const [state, setState] = useState<AsyncState<string[]>>({
    data: null,
    loading: false,
    error: null,
  })

  const fetchAccounts = useCallback(async () => {
    setState({ data: null, loading: true, error: null })
    try {
      const res = await fetch(endpoints.accounts)
      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: 'Failed to fetch accounts' }))
        throw new Error(err.message || `HTTP ${res.status}`)
      }
      const data = await res.json()
      setState({ data: data.accounts || [], loading: false, error: null })
    } catch (e) {
      setState({ data: null, loading: false, error: (e as Error).message })
    }
  }, [])

  return { ...state, fetchAccounts }
}

export type { ValidationResult, CredentialValidationResult, CredentialAttempt, HealthCheck, HealthResponse }
