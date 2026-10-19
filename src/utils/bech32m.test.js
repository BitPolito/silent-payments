import { expect, it } from 'vitest'
import { parsePatternInput, vanityPatternRange, vanitySearchStart } from './bech32m'
import { normalizeGenResponse } from './normalizeGen'
import fixtures from '../../api/core/test/key_vectors.json'
it('matches vanity boundaries on both networks and includes suffix checksum', () => {
  for (const [address,start] of [['sp1qqgabc',5],['tsp1qqgabc',6]]) {
    expect(vanitySearchStart(address,address.startsWith('tsp'))).toBe(start)
    expect(vanityPatternRange(address,'g','prefix',address.startsWith('tsp'))).toEqual({start,end:start+1})
    expect(vanityPatternRange(address,'abc','suffix',address.startsWith('tsp'))).toEqual({start:address.length-3,end:address.length})
  }
  expect(parsePatternInput('B!CAFE',3)).toEqual({value:'caf', removed:['b','!'], truncated:true})
})
it('rejects bad exported keys and inconsistent networks', () => {
  const f=fixtures[0]
  const payload={addresses:[f.address],network:f.network,key_material:{scan_priv_key:f.scan_priv_key,spend_priv_key:f.spend_priv_key}}
  expect(normalizeGenResponse(payload)?.addresses).toEqual([f.address])
  expect(normalizeGenResponse({...payload,network:'testnet'})).toBeNull()
  expect(normalizeGenResponse({...payload,key_material:{scan_priv_key:'00'.repeat(32),spend_priv_key:f.spend_priv_key}})).toBeNull()
  expect(normalizeGenResponse(null)).toBeNull()
})
