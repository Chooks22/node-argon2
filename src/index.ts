import { Buffer } from 'node:buffer'
import { argon2 as argon2_cb, type Argon2Algorithm, randomBytes, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'

let argon2 = promisify(argon2_cb)

// hard coded for now, unless node exposes which versions it supports
const VERSION = 'v=19'
const TAG_LENGTH = 16

// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
const DEFAULT_ARGON2_COST: Argon2Cost = {
  memory: 9216,
  iterations: 4,
  parallelism: 1,
}

type Argon2Cost = {
  memory: number
  iterations: number
  parallelism: number
}

type Argon2Params = {
  identifier: Argon2Algorithm
  salt: Buffer
  cost: Argon2Cost
}

function encode(derived_key: Buffer, input: Argon2Params): string {
  let hash = derived_key.toString('base64')
  let salt = input.salt.toString('base64')
  let cost = `m=${input.cost.memory},t=${input.cost.iterations},p=${input.cost.parallelism}`

  return `$${input.identifier}$${VERSION}$${cost}$${salt}$${hash}`
}

function decode(encoded: string): { params: Argon2Params, hash: Buffer } {
  let [algorithm, version, cost, salt, hash] = encoded.slice(1).split('$')

  if (version !== VERSION) {
    throw new Error(`Unsupported version. Received: ${version.slice('v='.length)}`)
  }

  type Keys = 'm' | 't' | 'p'
  let params: Record<Keys, number> = Object.create(null)

  for (let kv of cost.split(',')) {
    let [k, v] = kv.split('=')
    params[k as Keys] = Number(v)
  }

  return {
    params: {
      identifier: algorithm as Argon2Algorithm,
      cost: {
        memory: params.m,
        iterations: params.t,
        parallelism: params.p,
      },
      salt: Buffer.from(salt, 'base64'),
    },
    hash: Buffer.from(hash, 'base64'),
  }
}

function argon2_hash(data: string, params: Argon2Params) {
  return argon2(params.identifier, {
    message: Buffer.from(data, 'utf-8'),
    nonce: params.salt,
    memory: params.cost.memory,
    passes: params.cost.iterations,
    parallelism: params.cost.parallelism,
    tagLength: TAG_LENGTH,
  })
}

export async function hash(
  password: string,
  cost: Argon2Cost = DEFAULT_ARGON2_COST,
  algorithm: Argon2Algorithm = 'argon2id',
): Promise<string> {
  let params: Argon2Params = {
    identifier: algorithm,
    salt: randomBytes(16),
    cost,
  }

  let derived_key = await argon2_hash(password, params)

  return encode(derived_key, params)
}

export type VerifyInput = {
  hash: string
  password: string
}

export async function verify(data: VerifyInput): Promise<boolean> {
  try {
    let { hash, params } = decode(data.hash)

    let derived_key = await argon2_hash(data.password, params)

    return timingSafeEqual(derived_key, hash)
  } catch {
    return false
  }
}
