import { Router, Response } from 'express'
import { apps, releases, testers } from '../store'
import { inviteLimiter } from '../middleware/rateLimiter'
import {
  createDevelopmentDownloadToken,
  createOpaqueToken,
  hashOpaqueToken,
} from '../services/testerAccess'
import { GitHubStorageService } from '../services/githubStorage'

const router = Router()

router.get('/invites/:token', inviteLimiter, async (req, res: Response): Promise<void> => {
  const token = String(req.params.token || '')
  if (token.length < 32 || token.length > 100) {
    res.status(404).json({ error: 'Invitation not found or expired' })
    return
  }
  const invitation = await testers.findInviteByHash(hashOpaqueToken(token))
  if (!invitation || (
    invitation.tester.status === 'invited'
    && Number(invitation.tester.invite_expires_at) <= Math.floor(Date.now() / 1000)
  )) {
    res.status(404).json({ error: 'Invitation not found or expired' })
    return
  }
  res.json({
    invitation: {
      email: invitation.tester.email,
      name: invitation.tester.name,
      expires_at: invitation.tester.invite_expires_at,
      claimed: invitation.tester.status === 'active',
    },
    app: invitation.app,
  })
})

router.post('/invites/:token/claim', inviteLimiter, async (req, res: Response): Promise<void> => {
  const token = String(req.params.token || '')
  if (token.length < 32 || token.length > 100) {
    res.status(404).json({ error: 'Invitation not found or expired' })
    return
  }
  const accessToken = createOpaqueToken()
  const accepted = await testers.acceptInvite({
    tokenHash: hashOpaqueToken(token),
    accessTokenHash: hashOpaqueToken(accessToken),
    accessExpiresAt: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
  })
  if (!accepted) {
    res.status(404).json({ error: 'Invitation not found, expired, or already claimed' })
    return
  }
  res.json({
    access_token: accessToken,
    access_expires_at: Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60,
    app: accepted.app,
    tester: {
      email: accepted.tester.email,
      name: accepted.tester.name,
    },
  })
})

router.get('/apps/:appId/releases', async (req, res: Response): Promise<void> => {
  const appId = String(req.params.appId)
  const token = String(req.get('x-tester-token') || '')
  if (!token || !(await testers.hasAccess(appId, hashOpaqueToken(token)))) {
    res.status(401).json({ error: 'A valid Development Store tester session is required' })
    return
  }

  const app = await apps.findById(appId)
  if (!app) {
    res.status(404).json({ error: 'App not found' })
    return
  }
  const developmentReleases = await releases.listByAppAndEnvironment(appId, 'development')
  res.json({
    app: {
      id: app.id,
      name: app.name,
      package_name: app.package_name,
      icon_url: app.icon_url,
    },
    releases: developmentReleases.map(release => ({
      ...release,
      download_url: `${GitHubStorageService.publicDownloadUrl(release.id)}?download_token=${encodeURIComponent(
        createDevelopmentDownloadToken(release.id, appId, hashOpaqueToken(token)),
      )}`,
    })),
  })
})

export default router
