import { useState, useCallback } from 'react'
import { generateSqliVariants } from '../engines/sqli.js'
import { generateXssVariants } from '../engines/xss.js'
import { generateCmdiVariants } from '../engines/cmdi.js'
import { generateLfiVariants } from '../engines/lfi.js'
import { generateSsrfVariants } from '../engines/ssrf.js'
import { generateSstiVariants } from '../engines/ssti.js'
import { generateXxeVariants } from '../engines/xxe.js'
import { EVASION_LAYERS, TARGETS } from '../data/techniques.js'

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
    setVariants([])
    setError(null)
  }, [])

  const changeTarget = useCallback((newTarget) => {
    setTarget(newTarget)
    setActiveLayers((previous) => previous.filter((layerId) => {
      const layer = EVASION_LAYERS[category]?.find((candidate) => candidate.id === layerId)
      return !layer?.targets || layer.targets.includes(newTarget)
    }))
    setVariants([])
    setError(null)
  }, [category])

  const changePayload = useCallback((newPayload) => {
    setInputPayload(newPayload)
    setVariants([])
    setError(null)
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
      const results = engine(inputPayload, activeLayers, target)
      if (results.length <= 1) {
        setVariants([])
        setError('The selected layers are not applicable to this payload and target')
      } else {
        setVariants(results)
        setError(null)
      }
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
    setTarget: changeTarget,
    inputPayload,
    setInputPayload: changePayload,
    activeLayers,
    toggleLayer,
    variants,
    generate,
    clearAll,
    error,
  }
}
