import { describe, expect, it } from 'vitest'
import { accessOf, typeEnumName, TypeEnum } from '../../src/meta/constants'
import { parseClassName } from '../../src/meta/names'

describe('parseClassName', () => {
  it.each([
    ['System.String', { namespace: 'System', names: ['String'] }],
    ['Player', { namespace: '', names: ['Player'] }],
    ['Game.UI.Menu+Button', { namespace: 'Game.UI', names: ['Menu', 'Button'] }],
    ['Game.UI.Menu/Button/Icon', { namespace: 'Game.UI', names: ['Menu', 'Button', 'Icon'] }],
    ['Outer+Inner.WithDot', { namespace: '', names: ['Outer', 'Inner.WithDot'] }],
    ['System.Collections.Generic.List`1', { namespace: 'System.Collections.Generic', names: ['List`1'] }]
  ])('%s', (input, expected) => {
    expect(parseClassName(input)).toEqual(expected)
  })
})

describe('constants', () => {
  it('maps member access flags', () => {
    expect([0x6, 0x1, 0x3, 0x4, 0x5, 0x2, 0x0].map(accessOf)).toEqual([
      'public',
      'private',
      'internal',
      'protected',
      'protected internal',
      'private protected',
      'compiler-controlled'
    ])
    expect(accessOf(0x16)).toBe('public') // STATIC | PUBLIC
  })

  it('names type enums', () => {
    expect(typeEnumName(TypeEnum.GENERICINST)).toBe('GENERICINST')
    expect(typeEnumName(0x99)).toBe('0x99')
  })
})
