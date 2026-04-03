import { useState, useCallback } from 'react'
import { generateSqliVariants } from '../engines/sqli'
import { generateXssVariants } from '../engines/xss'
import { generateCmdiVariants } from '../engines/cmdi'
import { generateLfiVariants } from '../engines/lfi'
import { generateSsrfVariants } from '../engines/ssrf'
import { generateSstiVariants } from '../engines/ssti'
import { generateXxeVariants } from '../engines/xxe'
import { TARGETS } from '../data/techniques'

const ENGINE_MAP = {
  sqli: generateSqliVariants,
  xss: generateXssVariants,
  cmdi: generateCmdiVariants,
  lfi: generateLfiVariants,
  ssrf: generateSsrfVariants,
  ssti: generateSstiVariants,
  xxe: generateXxeVariants,
}

export default function useWafBypass() {
  const [category, setCategory] = useState('sqli')
  const [target, setTarget] = useState('mysql')
  const [inputPayload, setInputPayload] = useState('')
  const [activeLayers, setActiveLayers] = useState([])
  const [variants, setVariants] = useState([])
  const [error, setError] = useState(null)

  const changeCategory = useCallback((newCategory) => {
    setCategory(newCategory)
    // Set default target for new category
    const targets = TARGETS[newCategory]
    if (targets && targets.length > 0) {
      setTarget(targets[0].id)
    }
    // Clear state
    setActiveLayers([])
    setVariants([])
    setInputPayload('')
    setError(null)
  }, [])

  const toggleLayer = useCallback((layerId) => {
    setActiveLayers((prev) =>
      prev.includes(layerId) ? prev.filter((l) => l !== layerId) : [...prev, layerId]
    )
  }, [])

  const generate = useCallback(() => {
    const engine = ENGINE_MAP[category]
    if (!engine || !inputPayload.trim()) {
      setVariants([])
      setError(null)
      return
    }

    if (activeLayers.length === 0) {
      setError('Select at least one evasion layer')
      return
    }

    try {
      const results = engine(inputPayload.trim(), activeLayers, target)
      setVariants(results)
      setError(null)
    } catch (err) {
      setVariants([])
      setError(`Engine error: ${err.message}`)
    }
  }, [category, inputPayload, activeLayers, target])

  const clearAll = useCallback(() => {
    setInputPayload('')
    setVariants([])
    setError(null)
  }, [])

  return {
    category,
    setCategory: changeCategory,
    target,
    setTarget,
    inputPayload,
    setInputPayload,
    activeLayers,
    toggleLayer,
    variants,
    generate,
    clearAll,
    error,
  }
}
