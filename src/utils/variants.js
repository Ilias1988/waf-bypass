/**
 * Build a deterministic, fairly distributed result set.
 *
 * Engines may generate many candidates. The UI promises that selected layers
 * are represented, so reserve one slot per selected layer before filling the
 * remaining slots in engine order. The original payload is metadata, not one
 * of the advertised bypass variants.
 */
export function finalizeVariants(allVariants, selectedLayers, maxBypasses = 12) {
  const original = allVariants.find((variant) => variant.label === 'Original') ?? {
    payload: '',
    label: 'Original',
    layers: [],
  }

  const keyFor = (variant) => variant.bytesBase64
    ? `bytes:${variant.encoding ?? ''}:${variant.bytesBase64}`
    : `text:${variant.payload}`

  const originalKey = keyFor(original)
  const selectedLayerSet = new Set(selectedLayers)
  const candidatesByKey = new Map()
  for (const variant of allVariants) {
    if (!variant || typeof variant.payload !== 'string') continue
    const key = keyFor(variant)
    if (key === originalKey) continue
    const existing = candidatesByKey.get(key)
    if (!existing) {
      const layers = [...new Set((variant.layers ?? []).filter((layer) => selectedLayerSet.has(layer)))]
      if (layers.length === 0) continue
      candidatesByKey.set(key, {
        ...variant,
        layers,
        validity: variant.validity ?? 'conditional',
      })
      continue
    }
    existing.layers = [...new Set([
      ...(existing.layers ?? []),
      ...(variant.layers ?? []).filter((layer) => selectedLayerSet.has(layer)),
    ])]
  }
  const candidates = [...candidatesByKey.values()]

  const selected = []
  const selectedKeys = new Set()
  const coveredLayers = new Set()

  const add = (variant) => {
    const key = keyFor(variant)
    if (selectedKeys.has(key) || selected.length >= maxBypasses) return
    selected.push(variant)
    selectedKeys.add(key)
    variant.layers?.forEach((layer) => coveredLayers.add(layer))
  }

  for (const layer of selectedLayers) {
    if (coveredLayers.has(layer)) continue
    const representative = candidates.find((variant) =>
      variant.layers?.includes(layer) && !selectedKeys.has(keyFor(variant)))
    if (representative) add(representative)
  }

  for (const variant of candidates) add(variant)

  return [original, ...selected]
}

export function conditional(note) {
  return { validity: 'conditional', note }
}

export function validated(note = '') {
  return { validity: 'validated', ...(note ? { note } : {}) }
}
