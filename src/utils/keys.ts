import { randomBytes } from 'crypto'

export function generatePublicKey(): string {
  return 'pk_live_' + randomBytes(24).toString('base64url')
}

export function generateSecretKey(): string {
  return 'sk_live_' + randomBytes(24).toString('base64url')
}
