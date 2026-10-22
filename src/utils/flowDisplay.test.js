import { describe, expect, it } from 'vitest'
import { scriptTypeLabel } from './flowDisplay'

describe('transaction input script labels', () => {
  it('recognizes a full 32-byte Taproot witness program', () => {
    expect(scriptTypeLabel('512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')).toBe('P2TR')
    expect(scriptTypeLabel('5120' + '00'.repeat(20))).toBe('script')
  })
  it('keeps legacy and witness-key-hash input labels distinct', () => {
    expect(scriptTypeLabel('0014' + '12'.repeat(20))).toBe('P2WPKH')
    expect(scriptTypeLabel('76a914' + '12'.repeat(20) + '88ac')).toBe('P2PKH')
  })
})
