import assert from 'assert'
import { createHmac } from 'crypto'
import { verifyGitHubWebhookSignature } from '../services/githubApp'

const secret = 'github-webhook-test-secret'
const body = Buffer.from('{"zen":"Keep it logically awesome."}')
const signature = `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`

assert.strictEqual(verifyGitHubWebhookSignature(body, signature, secret), true)
assert.strictEqual(verifyGitHubWebhookSignature(Buffer.from(`${body.toString()} `), signature, secret), false)
assert.strictEqual(verifyGitHubWebhookSignature(body, undefined, secret), false)
assert.strictEqual(verifyGitHubWebhookSignature(body, 'sha1=invalid', secret), false)

console.log('GitHub webhook signature tests passed.')
