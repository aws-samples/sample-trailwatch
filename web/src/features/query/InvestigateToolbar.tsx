// Investigate toolbar: time window + account scope + seed input.
//
// Three controls drive every scenario run on this page:
//
//   1. Time window — required choice; presets dropdown for common windows.
//   2. Accounts — adaptive picker. Inline chips when 7 or fewer accounts
//      are known (the responder can see + toggle everything at a glance);
//      a controlled popover when more, with "select all synced" / "clear"
//      affordances.
//   3. Seed — single text box with smart-detect of type. Presence of a
//      seed reorders scenarios in the parent list (parent-side wiring;
//      this component just exposes the seed value via onChange).
//
// State lives in useToolbarState (URL-persistent) so refresh/back-button
// retain the investigation context. Popovers use usePopover, which wires
// click-outside and Escape close — replacing the native <details> element
// whose only-self-closes-on-summary-click behavior trapped stale dropdowns.

import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Calendar, ChevronDown, Database, X } from 'lucide-react'
import { endpoints } from '../../config/api'
import { usePopover } from '../../comm/usePopover'
import { detectSeedType, seedTypeLabel, type SeedType } from './seedDetection'
import { useToolbarState } from './useToolbarState'

interface DiscoverableAccount {
  account_id: string
  name?: string
  source: 'manual' | 'organizations' | 'unresolved'
  has_data: boolean
  session_count: number
}

interface Props {
  // The parent reads the toolbar's state to decide how to scope scenario
  // runs and to reorder scenarios when a seed is set.
  onChange?: (s: {
    timeStart: string
    timeEnd: string
    accountIds: string[]
    seed: string
    seedType: SeedType
  }) => void
  // clearSignal is a parent-driven request to clear a specific filter.
  // Bumping seq with a non-null kind tells the toolbar to reset that field.
  // Used by the active-filters chip strip rendered by the parent.
  clearSignal?: { seq: number; kind: 'time' | 'accounts' | 'seed' | null }
  // setSeedSignal is a parent-driven request to populate the seed field
  // with a specific value (and optional explicit type override). Used by
  // the click-to-pivot affordance on result-table cells: clicking an ARN
  // pushes that ARN into the toolbar so scenarios reorder around it.
  setSeedSignal?: { seq: number; value: string; type?: SeedType }
}

const TIME_PRESETS: { id: 'last_24h' | 'last_7d' | 'last_30d' | 'custom_clear'; labelKey: string }[] = [
  { id: 'last_24h', labelKey: 'investigateToolbar.preset.last24h' },
  { id: 'last_7d', labelKey: 'investigateToolbar.preset.last7d' },
  { id: 'last_30d', labelKey: 'investigateToolbar.preset.last30d' },
  { id: 'custom_clear', labelKey: 'investigateToolbar.preset.clear' },
]

const SEED_TYPE_OPTIONS: SeedType[] = ['arn', 'access_key', 'ip', 'account', 'user', 'role']

// Above this many discoverable accounts, switch from inline chips to a
// popover. Tuned so the chip strip does not horizontally overflow on the
// typical responder's screen.
const CHIP_STRIP_MAX = 7

export function InvestigateToolbar({ onChange, clearSignal, setSeedSignal }: Props) {
  const { t } = useTranslation()
  const tb = useToolbarState()

  const [accounts, setAccounts] = useState<DiscoverableAccount[]>([])
  const [accountsLoading, setAccountsLoading] = useState(true)

  const presetsPopover = usePopover()
  const accountsPopover = usePopover()

  // Close the other popover whenever this one opens, so they cannot render
  // simultaneously and overlap. Effects compare to a ref to detect open
  // transitions and avoid an infinite close-each-other loop.
  useEffect(() => {
    if (presetsPopover.isOpen) accountsPopover.close()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [presetsPopover.isOpen])
  useEffect(() => {
    if (accountsPopover.isOpen) presetsPopover.close()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accountsPopover.isOpen])

  // Surface state to the parent on every change so it can scope scenario
  // runs and trigger the seed-driven scenario reorder.
  useEffect(() => {
    onChange?.({
      timeStart: tb.state.timeStart,
      timeEnd: tb.state.timeEnd,
      accountIds: tb.state.accountIds,
      seed: tb.state.seed,
      seedType: tb.state.seedType,
    })
  }, [tb.state.timeStart, tb.state.timeEnd, tb.state.accountIds, tb.state.seed, tb.state.seedType, onChange])

  // React to the parent's clear-this-filter signal. Each unique seq triggers
  // exactly one clear; the kind names which filter to drop. Skips seq=0
  // (no-op initial value) so we do not clear on mount.
  useEffect(() => {
    if (!clearSignal || clearSignal.seq === 0 || !clearSignal.kind) return
    if (clearSignal.kind === 'time') {
      tb.applyPreset('custom_clear')
    } else if (clearSignal.kind === 'accounts') {
      tb.setAccountIds([])
    } else if (clearSignal.kind === 'seed') {
      tb.setSeed('')
      tb.setSeedTypeOverride(undefined)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clearSignal?.seq])

  // React to the parent's set-seed signal. Used by click-to-pivot in result
  // tables: a click on an ARN cell asks the toolbar to adopt that ARN.
  useEffect(() => {
    if (!setSeedSignal || setSeedSignal.seq === 0 || !setSeedSignal.value) return
    tb.setSeed(setSeedSignal.value)
    if (setSeedSignal.type) {
      tb.setSeedTypeOverride(setSeedSignal.type)
    } else {
      tb.setSeedTypeOverride(undefined)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [setSeedSignal?.seq])

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const res = await fetch(endpoints.accountsDiscoverable)
        if (!res.ok) return
        const data = (await res.json()) as { accounts: DiscoverableAccount[] }
        if (!cancelled) setAccounts(data.accounts || [])
      } catch {
        /* silent — toolbar still usable without account list */
      } finally {
        if (!cancelled) setAccountsLoading(false)
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [])

  const detectedType = useMemo(() => detectSeedType(tb.state.seed), [tb.state.seed])

  const dataAccounts = accounts.filter(a => a.has_data)
  const useChipStrip = accounts.length > 0 && accounts.length <= CHIP_STRIP_MAX

  function toggleAccount(id: string, checked: boolean) {
    if (checked) {
      tb.setAccountIds(Array.from(new Set([...tb.state.accountIds, id])))
    } else {
      tb.setAccountIds(tb.state.accountIds.filter(x => x !== id))
    }
  }

  function selectAllDataAccounts() {
    tb.setAccountIds(dataAccounts.map(a => a.account_id))
  }

  function clearAccounts() {
    tb.setAccountIds([])
  }

  return (
    <div className="px-6 py-3 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900">
      <div className="flex flex-wrap items-end gap-3">
        {/* Time window */}
        <div className="flex flex-col gap-1">
          <label className="text-[10px] font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">
            <Calendar className="inline w-3 h-3 mr-1" />
            {t('investigateToolbar.timeWindow')}
          </label>
          <div className="flex items-center gap-1.5">
            <input
              type="date"
              value={tb.state.timeStart}
              onChange={(e) => tb.setTimeStart(e.target.value)}
              className="px-2 py-1 text-xs rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
            <span className="text-xs text-gray-400">→</span>
            <input
              type="date"
              value={tb.state.timeEnd}
              onChange={(e) => tb.setTimeEnd(e.target.value)}
              className="px-2 py-1 text-xs rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
            <div className="relative">
              <button
                ref={presetsPopover.triggerRef}
                type="button"
                onClick={presetsPopover.toggle}
                aria-haspopup="menu"
                aria-expanded={presetsPopover.isOpen}
                className="px-2 py-1 text-[10px] rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 inline-flex items-center gap-0.5"
              >
                {t('investigateToolbar.presets')}
                <ChevronDown className="w-3 h-3" />
              </button>
              {presetsPopover.isOpen && (
                <div
                  ref={presetsPopover.panelRef}
                  role="menu"
                  className="absolute right-0 top-full mt-1 z-20 min-w-[140px] rounded border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-lg"
                >
                  {TIME_PRESETS.map(p => (
                    <button
                      key={p.id}
                      type="button"
                      role="menuitem"
                      onClick={() => { tb.applyPreset(p.id); presetsPopover.close() }}
                      className="w-full text-left px-3 py-1.5 text-[11px] text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                      {t(p.labelKey)}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Accounts: chip strip when small, popover when many */}
        <div className="flex flex-col gap-1 min-w-[200px] flex-1 max-w-[640px]">
          <div className="flex items-center justify-between">
            <label className="text-[10px] font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">
              <Database className="inline w-3 h-3 mr-1" />
              {t('investigateToolbar.accounts.label')}
            </label>
            {tb.state.accountIds.length > 0 && (
              <button
                type="button"
                onClick={clearAccounts}
                className="text-[10px] text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 hover:underline"
              >
                {t('investigateToolbar.accounts.clear')}
              </button>
            )}
          </div>

          {accountsLoading ? (
            <div className="text-[11px] text-gray-500">{t('investigateToolbar.accounts.loading')}</div>
          ) : useChipStrip ? (
            <AccountChipStrip
              accounts={accounts}
              selected={tb.state.accountIds}
              onToggle={toggleAccount}
              onSelectAll={selectAllDataAccounts}
            />
          ) : (
            <AccountPopover
              accounts={accounts}
              selected={tb.state.accountIds}
              onToggle={toggleAccount}
              onSelectAll={selectAllDataAccounts}
              onClear={clearAccounts}
              popover={accountsPopover}
            />
          )}
        </div>

        {/* Seed input */}
        <div className="flex flex-col gap-1 flex-1 min-w-[260px]">
          <label className="text-[10px] font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">
            {t('investigateToolbar.seed.label')}
          </label>
          <div className="flex items-center gap-1.5">
            <input
              type="text"
              value={tb.state.seed}
              onChange={(e) => tb.setSeed(e.target.value)}
              placeholder={t('investigateToolbar.seed.placeholder')}
              className="flex-1 px-2 py-1 text-xs font-mono rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
            {tb.state.seed && (
              <button
                type="button"
                onClick={() => tb.setSeed('')}
                title={t('investigateToolbar.seed.clear')}
                className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
          {tb.state.seed && (
            <div className="flex items-center gap-1.5 text-[10px] text-gray-500 dark:text-gray-400">
              <span>{t('investigateToolbar.seed.detectedAs')}</span>
              <select
                value={tb.state.seedTypeOverride ?? detectedType}
                onChange={(e) => {
                  const v = e.target.value as SeedType
                  tb.setSeedTypeOverride(v === detectedType ? undefined : v)
                }}
                className="px-1 py-0.5 text-[10px] rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
              >
                {SEED_TYPE_OPTIONS.map(opt => (
                  <option key={opt} value={opt}>{seedTypeLabel(opt)}</option>
                ))}
              </select>
              {tb.state.seedTypeOverride && (
                <button
                  type="button"
                  onClick={() => tb.setSeedTypeOverride(undefined)}
                  className="text-[10px] text-blue-600 dark:text-blue-400 hover:underline"
                >
                  {t('investigateToolbar.seed.useDetected', { type: seedTypeLabel(detectedType) })}
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// AccountChipStrip renders one toggleable chip per account, inline. Used
// when the user has 7 or fewer accounts known to the app — the entire
// scope is visible without opening anything.
function AccountChipStrip({
  accounts,
  selected,
  onToggle,
  onSelectAll,
}: {
  accounts: DiscoverableAccount[]
  selected: string[]
  onToggle: (id: string, checked: boolean) => void
  onSelectAll: () => void
}) {
  const { t } = useTranslation()
  const allSyncedSelected =
    accounts.filter(a => a.has_data).every(a => selected.includes(a.account_id)) &&
    accounts.some(a => a.has_data)

  return (
    <div className="flex flex-wrap gap-1.5 items-center">
      <button
        type="button"
        onClick={onSelectAll}
        disabled={allSyncedSelected}
        className="px-2 py-1 text-[10px] rounded border border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/40 disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {t('investigateToolbar.accounts.selectAllSynced')}
      </button>
      {accounts.map(a => {
        const isSelected = selected.includes(a.account_id)
        const disabled = !a.has_data
        return (
          <button
            key={a.account_id}
            type="button"
            disabled={disabled}
            onClick={() => onToggle(a.account_id, !isSelected)}
            title={disabled ? t('investigateToolbar.accounts.noDataTooltip') : undefined}
            className={`inline-flex items-center gap-1 px-2 py-1 text-[11px] rounded border transition-colors ${
              isSelected
                ? 'border-blue-600 bg-blue-600 text-white hover:bg-blue-700'
                : disabled
                ? 'border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-gray-400 cursor-not-allowed'
                : 'border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
            }`}
          >
            <span className="font-mono">{a.account_id}</span>
            {a.name && <span className={isSelected ? 'opacity-90' : 'text-gray-500'}>({a.name})</span>}
            {!a.has_data && <span className="text-[9px] opacity-70">— {t('investigateToolbar.accounts.notSynced')}</span>}
          </button>
        )
      })}
    </div>
  )
}

// AccountPopover renders a button + click-outside-closing panel of
// checkboxes. Used when the chip strip would overflow.
function AccountPopover({
  accounts,
  selected,
  onToggle,
  onSelectAll,
  onClear,
  popover,
}: {
  accounts: DiscoverableAccount[]
  selected: string[]
  onToggle: (id: string, checked: boolean) => void
  onSelectAll: () => void
  onClear: () => void
  popover: ReturnType<typeof usePopover>
}) {
  const { t } = useTranslation()
  const summaryText = useMemo(() => {
    if (selected.length === 0) return t('investigateToolbar.accounts.none')
    const dataIds = accounts.filter(a => a.has_data).map(a => a.account_id)
    if (selected.length === dataIds.length && dataIds.every(id => selected.includes(id))) {
      return t('investigateToolbar.accounts.allWithData', { count: dataIds.length })
    }
    const names = selected.slice(0, 3).map(id => accounts.find(x => x.account_id === id)?.name || id)
    const extra = selected.length - names.length
    return extra > 0 ? `${names.join(', ')} +${extra}` : names.join(', ')
  }, [accounts, selected, t])

  return (
    <div className="relative">
      <button
        ref={popover.triggerRef}
        type="button"
        onClick={popover.toggle}
        aria-haspopup="listbox"
        aria-expanded={popover.isOpen}
        className="w-full px-2 py-1 text-xs rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white inline-flex items-center justify-between gap-2"
      >
        <span className="truncate">{summaryText}</span>
        <ChevronDown className="w-3 h-3 shrink-0" />
      </button>
      {popover.isOpen && (
        <div
          ref={popover.panelRef}
          role="listbox"
          aria-multiselectable="true"
          className="absolute left-0 top-full mt-1 z-20 w-[340px] max-h-[320px] overflow-y-auto rounded border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 shadow-lg"
        >
          <div className="flex items-center justify-between px-2 py-1.5 border-b border-gray-200 dark:border-gray-700 sticky top-0 bg-white dark:bg-gray-800">
            <button
              type="button"
              onClick={onSelectAll}
              className="text-[10px] text-blue-600 dark:text-blue-400 hover:underline"
            >
              {t('investigateToolbar.accounts.selectAllSynced')}
            </button>
            <button
              type="button"
              onClick={onClear}
              className="text-[10px] text-gray-500 dark:text-gray-400 hover:underline"
            >
              {t('investigateToolbar.accounts.clear')}
            </button>
          </div>
          {accounts.map(a => {
            const checked = selected.includes(a.account_id)
            return (
              <label
                key={a.account_id}
                className={`flex items-center gap-2 px-3 py-1.5 text-xs cursor-pointer ${a.has_data ? 'hover:bg-gray-50 dark:hover:bg-gray-700' : 'opacity-60'}`}
                title={a.has_data ? '' : t('investigateToolbar.accounts.noDataTooltip')}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={(e) => onToggle(a.account_id, e.target.checked)}
                  className="rounded text-blue-600 focus:ring-blue-500"
                />
                <span className="font-mono text-gray-700 dark:text-gray-300">{a.account_id}</span>
                {a.name && <span className="text-gray-500 dark:text-gray-400">({a.name})</span>}
                {a.has_data ? (
                  <span className="ml-auto text-[9px] text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/30 px-1.5 py-0.5 rounded">
                    {t('investigateToolbar.accounts.dataAvailable')}
                  </span>
                ) : (
                  <span className="ml-auto text-[9px] text-gray-500 bg-gray-100 dark:bg-gray-700 px-1.5 py-0.5 rounded">
                    {t('investigateToolbar.accounts.notSynced')}
                  </span>
                )}
              </label>
            )
          })}
        </div>
      )}
    </div>
  )
}
