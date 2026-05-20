// usePopover wires up the standard "open this floating panel and close it
// when the user clicks outside or presses Escape" behavior.
//
// Used instead of the native <details> element because <details> only closes
// when its <summary> is clicked again — a known quirk that traps stale
// popovers around the page when users move on.
//
// Usage:
//   const popover = usePopover()
//   <button ref={popover.triggerRef} onClick={popover.toggle}>...</button>
//   {popover.isOpen && (
//     <div ref={popover.panelRef}>...panel content...</div>
//   )}

import { useCallback, useEffect, useRef, useState } from 'react'

export interface PopoverHandle {
  isOpen: boolean
  open: () => void
  close: () => void
  toggle: () => void
  triggerRef: React.MutableRefObject<HTMLButtonElement | null>
  panelRef: React.MutableRefObject<HTMLDivElement | null>
}

export function usePopover(): PopoverHandle {
  const [isOpen, setIsOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement | null>(null)
  const panelRef = useRef<HTMLDivElement | null>(null)

  const open = useCallback(() => setIsOpen(true), [])
  const close = useCallback(() => setIsOpen(false), [])
  const toggle = useCallback(() => setIsOpen(v => !v), [])

  useEffect(() => {
    if (!isOpen) return

    function onPointer(e: MouseEvent | TouchEvent) {
      const target = e.target as Node | null
      if (!target) return
      // Click inside the panel or on the trigger? Keep open.
      if (panelRef.current && panelRef.current.contains(target)) return
      if (triggerRef.current && triggerRef.current.contains(target)) return
      setIsOpen(false)
    }

    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.stopPropagation()
        setIsOpen(false)
      }
    }

    document.addEventListener('mousedown', onPointer)
    document.addEventListener('touchstart', onPointer)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointer)
      document.removeEventListener('touchstart', onPointer)
      document.removeEventListener('keydown', onKey)
    }
  }, [isOpen])

  return { isOpen, open, close, toggle, triggerRef, panelRef }
}
