import { createHash, randomBytes } from 'crypto'
import { Router, Request, Response } from 'express'
import { AuthRequest, requireVerifiedAuth } from '../middleware/auth'
import { githubStore } from '../store/github'
import { createGitHubAppJwt, verifyGitHubWebhookSignature } from '../services/githubApp'

const router = Router()
const GITHUB_API = 'https://api.github.com'
const GITHUB_API_VERSION = '2022-11-28'
const OAUTH_STATE_TTL_SECONDS = 10 * 60

function requiredEnv(name: string): string {
  const value = process.env[name]
  if (!value) {
    throw Object.assign(new Error(`GitHub integration is not configured: ${name} is missing`), { status: 503 })
  }
  return value
}

function stateDigest(state: string): string {
  return createHash('sha256').update(state).digest('hex')
}

async function githubJson(url: string, init: Parameters<typeof fetch>[1] = {}): Promise<Record<string, any>> {
  let response: globalThis.Response
  try {
    response = await fetch(url, { ...init, signal: AbortSignal.timeout(10_000) })
  } catch {
    throw Object.assign(new Error('GitHub could not be reached'), { status: 502 })
  }

  let body: Record<string, any>
  try {
    body = await response.json() as Record<string, any>
  } catch {
    throw Object.assign(new Error('GitHub returned an invalid response'), { status: 502 })
  }
  if (!response.ok) {
    throw Object.assign(new Error('GitHub rejected the integration request'), { status: 502 })
  }
  return body
}

function appHeaders(token: string): Record<string, string> {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
    'User-Agent': 'Sproutly-Builds',
  }
}

function appJwt(): string {
  return createGitHubAppJwt(requiredEnv('GITHUB_APP_ID'), requiredEnv('GITHUB_APP_PRIVATE_KEY'))
}

router.post('/install', requireVerifiedAuth, async (req: AuthRequest, res: Response): Promise<void> => {
  const userId = req.userId
  if (!userId) {
    res.status(401).json({ error: 'Authentication required' })
    return
  }

  const app = await githubJson(`${GITHUB_API}/app`, { headers: appHeaders(appJwt()) })
  if (typeof app.slug !== 'string' || !/^[a-z0-9-]+$/.test(app.slug)) {
    throw Object.assign(new Error('GitHub App metadata is missing its slug'), { status: 502 })
  }

  const state = randomBytes(32).toString('base64url')
  await githubStore.createOAuthState({
    stateHash: stateDigest(state),
    userId,
    expiresAt: Math.floor(Date.now() / 1000) + OAUTH_STATE_TTL_SECONDS,
  })

  const installUrl = new URL(`https://github.com/apps/${app.slug}/installations/new`)
  installUrl.searchParams.set('state', state)
  res.setHeader('Cache-Control', 'no-store')
  res.json({ url: installUrl.toString() })
})

router.get('/callback', async (req: Request, res: Response): Promise<void> => {
  const code = typeof req.query.code === 'string' ? req.query.code : ''
  const state = typeof req.query.state === 'string' ? req.query.state : ''
  const installationId = typeof req.query.installation_id === 'string' ? req.query.installation_id : ''
  if (!code || !state || !/^\d+$/.test(installationId)) {
    res.status(400).json({ error: 'GitHub authorization response is incomplete' })
    return
  }

  const userId = await githubStore.consumeOAuthState(stateDigest(state))
  if (!userId) {
    res.status(400).json({ error: 'GitHub authorization state is invalid or expired' })
    return
  }

  const tokenResponse = await githubJson('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: requiredEnv('GITHUB_CLIENT_ID'),
      client_secret: requiredEnv('GITHUB_CLIENT_SECRET'),
      code,
    }),
  })
  if (typeof tokenResponse.access_token !== 'string' || tokenResponse.error) {
    res.status(400).json({ error: 'GitHub authorization could not be completed' })
    return
  }

  const userHeaders = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${tokenResponse.access_token}`,
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
    'User-Agent': 'Sproutly-Builds',
  }
  let authorizedInstallation: Record<string, any> | undefined
  let page = 1
  let totalInstallations = Number.POSITIVE_INFINITY
  while ((page - 1) * 100 < totalInstallations) {
    const userInstallations = await githubJson(
      `${GITHUB_API}/user/installations?per_page=100&page=${page}`,
      { headers: userHeaders },
    )
    if (!Array.isArray(userInstallations.installations) || typeof userInstallations.total_count !== 'number') {
      throw Object.assign(new Error('GitHub returned an invalid installation list'), { status: 502 })
    }
    authorizedInstallation = userInstallations.installations
      .find((item: Record<string, any>) => String(item.id) === installationId)
    totalInstallations = userInstallations.total_count
    if (authorizedInstallation) break
    page += 1
  }
  if (!authorizedInstallation) {
    res.status(403).json({ error: 'This GitHub user is not authorized for the selected installation' })
    return
  }

  const installation = await githubJson(`${GITHUB_API}/app/installations/${installationId}`, {
    headers: appHeaders(appJwt()),
  })
  if (String(installation.id) !== installationId || !installation.account?.id || !installation.account?.login) {
    res.status(400).json({ error: 'GitHub installation could not be verified' })
    return
  }

  await githubStore.linkInstallation({
    installationId,
    userId,
    accountId: String(installation.account.id),
    accountLogin: String(installation.account.login),
    accountType: String(installation.account.type || ''),
    repositorySelection: String(installation.repository_selection || ''),
    suspendedAt: typeof installation.suspended_at === 'string' ? installation.suspended_at : null,
  })

  const consoleUrl = new URL('/console', process.env.GITHUB_CONSOLE_URL || 'https://sproutly-dev.vercel.app')
  consoleUrl.searchParams.set('github_install', 'connected')
  res.setHeader('Cache-Control', 'no-store')
  res.redirect(303, consoleUrl.toString())
})

router.post('/webhook', async (req: Request, res: Response): Promise<void> => {
  const secret = process.env.GITHUB_WEBHOOK_SECRET
  if (!secret) {
    res.status(503).json({ error: 'GitHub webhook is not configured' })
    return
  }
  if (!Buffer.isBuffer(req.body)) {
    res.status(400).json({ error: 'Webhook body must be raw JSON' })
    return
  }
  if (!verifyGitHubWebhookSignature(req.body, req.get('x-hub-signature-256'), secret)) {
    res.status(401).json({ error: 'Invalid GitHub webhook signature' })
    return
  }

  const deliveryId = req.get('x-github-delivery')
  const eventName = req.get('x-github-event')
  if (!deliveryId || deliveryId.length > 128 || !eventName) {
    res.status(400).json({ error: 'GitHub webhook headers are incomplete' })
    return
  }

  let payload: Record<string, any>
  try {
    payload = JSON.parse(req.body.toString('utf8'))
  } catch {
    res.status(400).json({ error: 'GitHub webhook body is invalid JSON' })
    return
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    res.status(400).json({ error: 'GitHub webhook payload must be a JSON object' })
    return
  }

  await githubStore.recordWebhook({ deliveryId, eventName, payload })
  if (
    (eventName === 'installation' || eventName === 'installation_repositories')
    && payload.installation
    && typeof payload.action === 'string'
  ) {
    await githubStore.syncInstallationWebhook(payload.installation, payload.action)
  }

  res.status(202).json({ received: true, delivery_id: deliveryId })
})

export default router
