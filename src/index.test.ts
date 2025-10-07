// Adapted from:
// https://github.com/better-auth/better-auth/blob/canary/packages/better-auth/src/crypto/password.test.ts
import { describe, expect, it } from 'vitest'
import { hash as hashPassword, verify as verifyPassword } from './index.ts'

describe('password hashing and verification', () => {
  it('should hash a password', async () => {
    let password = 'mySecurePassword123!'
    let hash = await hashPassword(password)
    expect(hash).toBeTruthy()
    expect(hash.split('$').length).toBe(6)
  })

  it('should verify a correct password', async () => {
    let password = 'correctPassword123!'
    let hash = await hashPassword(password)
    let isValid = await verifyPassword({ hash, password })
    expect(isValid).toBe(true)
  })

  it('should reject an incorrect password', async () => {
    let correctPassword = 'correctPassword123!'
    let incorrectPassword = 'wrongPassword456!'
    let hash = await hashPassword(correctPassword)
    let isValid = await verifyPassword({ hash, password: incorrectPassword })
    expect(isValid).toBe(false)
  })

  it('should generate different hashes for the same password', async () => {
    let password = 'samePassword123!'
    let hash1 = await hashPassword(password)
    let hash2 = await hashPassword(password)
    expect(hash1).not.toBe(hash2)
  })

  it('should handle long passwords', async () => {
    let password = 'a'.repeat(1000)
    let hash = await hashPassword(password)
    let isValid = await verifyPassword({ hash, password })
    expect(isValid).toBe(true)
  })

  it('should be case-sensitive', async () => {
    let password = 'CaseSensitivePassword123!'
    let hash = await hashPassword(password)
    let isValidLower = await verifyPassword({
      hash,
      password: password.toLowerCase(),
    })
    let isValidUpper = await verifyPassword({
      hash,
      password: password.toUpperCase(),
    })
    expect(isValidLower).toBe(false)
    expect(isValidUpper).toBe(false)
  })

  it('should handle Unicode characters', async () => {
    let password = 'пароль123!'
    let hash = await hashPassword(password)
    let isValid = await verifyPassword({ hash, password })
    expect(isValid).toBe(true)
  })
})
