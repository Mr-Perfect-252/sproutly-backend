import { Router, Response } from 'express'
import { v4 as uuid } from 'uuid'
import { z } from 'zod'
import { createClerkClient } from '@clerk/backend'
import { apps, releases, reviews, testers, users } from '../store'
import { requireAuth, requireVerifiedAuth, AuthRequest } from '../middleware/auth'
import { validateBody } from '../middleware/validator'
import { generatePublicKey, generateSecretKey } from '../utils/keys'
import { isIdLike } from '../utils/displayName'
import { GitHubStorageService } from '../services/githubStorage'
import { sendTesterInvite, testerInviteUrl } from '../services/inviteMailer'
import { createOpaqueToken, hashOpaqueToken } from '../services/testerAccess'

const router = Router()

const CLERK_SECRET_KEY = process.env.CLERK_SECRET_KEY || ''
const clerkClient = CLERK_SECRET_KEY ? createClerkClient({ secretKey: CLERK_SECRET_KEY }) : null

function looksLikeId(value: string, userId: string): boolean {
  const v = (value || '').trim()
  if (!v) return false
  if (v.toLowerCase() === userId.toLowerCase()) return true
  return isIdLike(v)
}

/**
 * Resolves a safe, human display name for a developer. Never falls back to
 * the raw Clerk/user id — only a real name, a real email's local part, or
 * the generic label "Developer".
 */
async function resolveDeveloperName(userId: string, userEmail: string, clientProvided: string): Promise<string> {
  const provided = (clientProvided || '').trim()
  if (provided && !looksLikeId(provided, userId)) return provided

  // The client didn't send a usable name — try to look up the real profile
  // from Clerk directly rather than deriving anything from the id.
  if (clerkClient) {
    try {
      const profile = await clerkClient.users.getUser(userId)
      const fullName = [profile.firstName, profile.lastName].filter(Boolean).join(' ').trim()
      if (fullName) return fullName
      const email = profile.emailAddresses?.[0]?.emailAddress || ''
      if (email && !email.endsWith('@apexhub.app')) return email.split('@')[0]
    } catch {
      // Clerk lookup failed — fall through to the generic label below.
    }
  }

  // Only trust userEmail's local part if it isn't the synthetic fallback
  // address (which is built from the id and would leak it right back out).
  const isSynthetic = !userEmail || userEmail.endsWith('@apexhub.app')
  if (!isSynthetic) {
    const localPart = userEmail.split('@')[0]
    if (localPart && !looksLikeId(localPart, userId)) return localPart
  }

  return 'Developer'
}

/** Defensive display-time guard for rows created before this fix — never render an id as a name. */
function sanitizeStoredName(storedDeveloperName: string | undefined, ownerName: string | undefined, ownerId: string): string {
  const primary = (storedDeveloperName || '').trim()
  if (primary && !looksLikeId(primary, ownerId)) return primary
  const fallback = (ownerName || '').trim()
  if (fallback && !looksLikeId(fallback, ownerId)) return fallback
  return 'Developer'
}


const CreateAppSchema = z.object({
  name: z.string().min(2, 'App name must be at least 2 characters').max(100),
  package_name: z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$/, 'Invalid package name format (e.g. com.example.myapp)'),
  description: z.string().max(2000).optional().default(''),
  category: z.string().max(50).optional().default('Utilities'),
  website_url: z.string().url('Invalid URL format').or(z.literal('')).optional().default(''),
  icon_url: z.string().url('Invalid icon URL format').or(z.literal('')).optional().default(''),
  screenshots: z.array(z.string().url('Invalid screenshot URL format')).max(8, 'Up to 8 screenshots allowed').optional().default([]),
  developer_name: z.string().max(100).optional().default(''),
})

const UpdateAppSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  description: z.string().max(2000).optional(),
  category: z.string().max(50).optional(),
  website_url: z.string().url().or(z.literal('')).optional(),
  icon_url: z.string().url().or(z.literal('')).optional(),
  screenshots: z.array(z.string().url('Invalid screenshot URL format')).max(8, 'Up to 8 screenshots allowed').optional(),
})

const ReviewSchema = z.object({
  user_name: z.string().min(2, 'Name must be at least 2 characters').max(50),
  rating: z.number().int().min(1).max(5),
  body: z.string().max(1000).optional().default(''),
})

const ReviewReplySchema = z.object({
  reply: z.string().trim().min(1, 'Reply cannot be empty').max(1000),
})

// ── Public routes ──────────────────────────────────────────────────────────

// GET /api/apps/dashboard/reviews — reviews for the signed-in developer's apps
router.get('/dashboard/reviews', requireVerifiedAuth, async (req: AuthRequest, res: Response): Promise<void> => {
  const ownedApps = await apps.listByOwner(req.userId || '')
  const appById = new Map(ownedApps.map(app => [app.id, app]))
  const reviewList = await reviews.listByApps(ownedApps.map(app => app.id))
  res.json({
    reviews: reviewList.map(review => ({
      ...review,
      app_name: appById.get(review.app_id)?.name || 'App',
      package_name: appById.get(review.app_id)?.package_name || '',
    })),
  })
})

// GET /api/apps — browse all public apps
router.get('/', async (req, res: Response): Promise<void> => {
  const { q, category, sort = 'downloads' } = req.query as Record<string, string>
  const appsList = await apps.listPublic({ q, category, sort })
  res.json({ apps: appsList })
})

// GET /api/apps/:pkg — single app detail (public)
router.get('/:pkg', async (req, res: Response): Promise<void> => {
  const target = String(req.params.pkg)
  const matched = await apps.findForDetail(target)

  if (!matched) {
    res.status(404).json({ error: 'App not found' })
    return
  }

  // Assemble aggregates and developer name
  const [owner, releaseList, reviewList] = await Promise.all([
    users.findById(matched.owner_id),
    releases.listVisibleByApp(matched.id),
    reviews.listByApp(matched.id, 50),
  ])

  // Live-release download total + rating aggregates (public semantics)
  const liveReleases = releaseList.filter(r => r.status === 'live')
  const totalDownloads = liveReleases.reduce((s, r) => s + (Number(r.downloads) || 0), 0)
  const reviewCount = reviewList.length
  const avgRating = reviewCount
    ? reviewList.reduce((s, r) => s + (Number(r.rating) || 0), 0) / reviewCount
    : 0

  // Strip secret/public keys and owner id from the public response
  const app: any = {
    id: matched.id,
    package_name: matched.package_name,
    name: matched.name,
    description: matched.description,
    icon_url: matched.icon_url,
    screenshots: (matched as any).screenshots || [],
    category: matched.category,
    website_url: matched.website_url,
    cert_fingerprint: matched.cert_fingerprint,
    created_at: matched.created_at,
    developer_name: sanitizeStoredName((matched as any).developer_name, owner?.name, matched.owner_id),
    avg_rating: avgRating,
    review_count: reviewCount,
    total_downloads: totalDownloads,
  }

  res.json({ app, releases: releaseList, reviews: reviewList })
})

// POST /api/apps/:pkg/reviews — submit a user review
router.post('/:pkg/reviews', validateBody(ReviewSchema), async (req, res: Response): Promise<void> => {
  const { user_name, rating, body = '' } = req.body

  const app = await apps.findByPackage(String(req.params.pkg))
  if (!app) {
    res.status(404).json({ error: 'App not found' })
    return
  }

  const review = await reviews.create({
    id: uuid(),
    app_id: app.id,
    user_name: user_name.trim(),
    rating,
    body: body.trim(),
  })

  res.status(201).json({ review })
})

// POST /api/apps/:pkg/reviews/:reviewId/reply — app owner reply
router.post('/:pkg/reviews/:reviewId/reply', requireVerifiedAuth, validateBody(ReviewReplySchema), async (req: AuthRequest, res: Response): Promise<void> => {
  const app = await apps.findByPackage(String(req.params.pkg))
  if (!app) {
    res.status(404).json({ error: 'App not found' })
    return
  }

  if (app.owner_id !== req.userId) {
    res.status(403).json({ error: 'Only this app’s owner can reply to its reviews' })
    return
  }

  const review = await reviews.reply(String(req.params.reviewId), app.id, req.body.reply)
  if (!review) {
    res.status(404).json({ error: 'Review not found' })
    return
  }

  res.json({ review })
})

// ── Authenticated routes ───────────────────────────────────────────────────

// GET /api/apps/dashboard/mine — developer's own apps
router.get('/dashboard/mine', requireAuth, async (req: AuthRequest, res: Response): Promise<void> => {
  const currentUserId = req.userId || 'developer'
  const appsWithReleases = await apps.listByOwner(currentUserId)
  res.json({ apps: appsWithReleases })
})

router.get('/:appId/testers', requireVerifiedAuth, async (req: AuthRequest, res: Response): Promise<void> => {
  const app = await apps.findByIdAndOwner(String(req.params.appId), req.userId || '')
  if (!app) {
    res.status(404).json({ error: 'App not found' })
    return
  }
  const rows = await testers.listByAppAndOwner(app.id, req.userId || '')
  res.json({ testers: rows })
})

router.post('/:appId/testers', requireVerifiedAuth, async (req: AuthRequest, res: Response): Promise<void> => {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : ''
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : ''
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    res.status(400).json({ error: 'A valid tester email is required' })
    return
  }
  if (name.length > 100) {
    res.status(400).json({ error: 'Tester name must be 100 characters or fewer' })
    return
  }

  const appId = String(req.params.appId)
  const app = await apps.findByIdAndOwner(appId, req.userId || '')
  if (!app) {
    res.status(404).json({ error: 'App not found' })
    return
  }
  const existing = await testers.listByAppAndOwner(appId, req.userId || '')
  if (existing.some(tester => tester.email.toLowerCase() === email)) {
    res.status(409).json({ error: 'This tester is already on the app' })
    return
  }

  const inviteToken = createOpaqueToken()
  const inviteUrl = testerInviteUrl(inviteToken)
  const tester = await testers.add({
    id: uuid(),
    appId,
    email,
    name,
    inviteTokenHash: hashOpaqueToken(inviteToken),
    inviteExpiresAt: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
  })

  try {
    await sendTesterInvite({ email, appName: app.name, inviteUrl })
  } catch (error) {
    try {
      await testers.remove(tester.id, app.id)
    } catch (cleanupError) {
      console.error('[Tester Invite] Failed to remove unsent invitation:', cleanupError)
    }
    const message = error instanceof Error ? error.message : 'Email delivery failed'
    res.status(502).json({ error: `Tester invitation could not be sent. ${message}` })
    return
  }

  res.status(201).json({ tester, invite_url: inviteUrl })
})

router.delete('/:appId/testers/:testerId', requireVerifiedAuth, async (req: AuthRequest, res: Response): Promise<void> => {
  const app = await apps.findByIdAndOwner(String(req.params.appId), req.userId || '')
  if (!app) {
    res.status(404).json({ error: 'App not found' })
    return
  }
  const removed = await testers.remove(
    String(req.params.testerId),
    app.id,
  )
  if (!removed) {
    res.status(404).json({ error: 'Tester or app not found' })
    return
  }
  res.json({ ok: true })
})

// POST /api/apps — create a new app entry
router.post('/', requireAuth, validateBody(CreateAppSchema), async (req: AuthRequest, res: Response): Promise<void> => {
  let { package_name, name, description, category, website_url, icon_url, screenshots, developer_name } = req.body
  const userId = req.userId || 'developer'
  const userEmail = req.userEmail || `${userId}@apexhub.app`

  // Resolve the developer display name: prefer the name the client sent (the
  // logged-in user's username); never derive it from the raw user/session id.
  const resolvedDeveloperName = await resolveDeveloperName(userId, userEmail, developer_name)

  // Generate a clean 6-character user identifier suffix to ensure namespace uniqueness across accounts
  const userPrefix = userId.replace(/[^a-zA-Z0-9]/g, '').slice(-6).toLowerCase() || 'usr'

  // If user registered a package name without a unique namespace, append or ensure user namespace
  const lowerPkg = package_name.toLowerCase()
  if (!lowerPkg.includes(userPrefix)) {
    // If it conflicts with an existing package name, namespace it with the user's unique identifier
    const existing = await apps.findByPackage(package_name)
    if (existing) {
      package_name = `${package_name}.${userPrefix}`
    }
  }

  const existingFinal = await apps.findByPackage(package_name)
  if (existingFinal) {
    res.status(409).json({ error: `Package name '${package_name}' is already taken. Please choose another.` })
    return
  }

  const id = uuid()
  const public_key = generatePublicKey()
  const secret_key = generateSecretKey()

  // Ensure owner user record exists to satisfy the apps.owner_id → users FK
  // before inserting the app row.
  await users.ensureExists({
    id: userId,
    email: userEmail,
    name: resolvedDeveloperName,
    password: '$2a$12$dummyhashforclerkuser',
  })

  await apps.create({
    id,
    owner_id: userId,
    package_name,
    name,
    description,
    category,
    website_url,
    icon_url,
    screenshots,
    public_key,
    secret_key,
    developer_name: resolvedDeveloperName,
    developer_id: userId,
  })

  const newApp = {
    id,
    package_name,
    name,
    description,
    category,
    website_url,
    icon_url: icon_url || '',
    screenshots: screenshots || [],
    public_key,
    secret_key,
    releases: [],
  }

  // Sync App manifest to GitHub Storage repo (Apex-Hub-Storage) for cross-session persistence.
  // Uses the Contents API (uploadFile) — plain JSON metadata, not an APK binary.
  try {
    const config = GitHubStorageService.getConfig()
    const manifestPath = `users/${userId}/apps/${package_name}/app.json`
    GitHubStorageService.uploadFile(
      config,
      manifestPath,
      Buffer.from(JSON.stringify(newApp, null, 2)),
      `feat(app): register ${package_name} manifest [user:${userId}]`
    ).catch((err: any) => console.warn('[GitHub App Manifest Sync Warning]', err?.message))
  } catch (err) {
    console.warn('[GitHub App Sync Warning]', err)
  }

  res.status(201).json({ app: newApp })
})

// PUT /api/apps/:id — update app metadata
router.put('/:id', requireAuth, validateBody(UpdateAppSchema), async (req: AuthRequest, res: Response): Promise<void> => {
  const app = await apps.findByIdAndOwner(String(req.params.id), req.userId || '')
  if (!app) {
    res.status(404).json({ error: 'App not found' })
    return
  }

  const { name, description, category, website_url, icon_url, screenshots } = req.body
  await apps.update(String(req.params.id), { name, description, category, website_url, icon_url, screenshots })

  res.json({ ok: true })
})

// DELETE /api/apps/:id
router.delete('/:id', requireAuth, async (req: AuthRequest, res: Response): Promise<void> => {
  const app = await apps.findByIdAndOwner(String(req.params.id), req.userId || '')
  if (!app) {
    res.status(404).json({ error: 'App not found' })
    return
  }
  await apps.remove(String(req.params.id))
  res.json({ ok: true })
})

export default router
