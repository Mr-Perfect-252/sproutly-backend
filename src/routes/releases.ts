import { Router, Response, Request } from 'express'
import multer from 'multer'
import path from 'path'
import fs from 'fs'
import https from 'https'
import http from 'http'
import { v4 as uuid } from 'uuid'
import { UPLOADS_DIR } from '../store/paths'
import { apps, releases, testers } from '../store'
import { requireAuth, requireVerifiedAuth, AuthRequest } from '../middleware/auth'
import { uploadLimiter } from '../middleware/rateLimiter'
import { parseApk, certFingerprintFromApkBuffer } from '../utils/apkParser'
import { storageService } from '../services/storage/storageService'
import { malwareScanner } from '../services/scanner/malwareScanner'
import { GitHubStorageService } from '../services/githubStorage'
import { hashOpaqueToken, createDevelopmentDownloadToken, getDevelopmentDownloadAccessHash } from '../services/testerAccess'

const router = Router()

/**
 * Resolve the signing-certificate fingerprint of the app's existing latest release
 * by re-parsing the stored APK. Returns null when it cannot be determined.
 */
async function existingReleaseCertFingerprint(appId: string): Promise<string | null> {
  try {
    const latest: any = await releases.latestByApp(appId)
    if (!latest?.id) return null
    const doFetch = (globalThis as any).fetch
    if (typeof doFetch !== 'function') return null
    const url = GitHubStorageService.publicDownloadUrl(latest.id)
    const res = await doFetch(url, { redirect: 'follow' })
    if (!res || !res.ok) return null
    const buf = Buffer.from(await res.arrayBuffer())
    return certFingerprintFromApkBuffer(buf) || null
  } catch (e: any) {
    console.warn('[Upload] Could not resolve existing release certificate:', e?.message)
    return null
  }
}

/**
 * Enforce "same signing key" between a new upload and the app's existing releases.
 * Returns an error message to reject with, or null to allow.
 *
 * Stored values may be legacy (unstable) fingerprints from before the fix, so on a
 * stored-vs-new mismatch we recompute the certificate from the app's existing APK and
 * compare certificates (the correct, stable check) rather than a per-build blob hash.
 */
async function sameSigningKeyError(app: any, meta: any): Promise<string | null> {
  const stored = app?.cert_fingerprint
  if (!stored) return null
  if (stored === meta.certFingerprint) return null
  if (meta.certFingerprintLegacy && stored === meta.certFingerprintLegacy) return null

  const existing = await existingReleaseCertFingerprint(app.id)
  if (existing) {
    if (existing === meta.certFingerprint) return null
    return 'Certificate fingerprint mismatch. APK must be signed with the same key as the first upload.'
  }
  // Cannot verify (e.g. existing APK unavailable) — don't block a legitimate update.
  console.warn('[Upload] Signing-certificate verification unavailable for app', app.id, '— allowing upload.')
  return null
}

/** Store the stable certificate fingerprint once a release is accepted. */
async function rememberCertFingerprint(appId: string, app: any, meta: any): Promise<void> {
  if (meta.certFingerprint && app.cert_fingerprint !== meta.certFingerprint) {
    await apps.update(String(appId), { cert_fingerprint: meta.certFingerprint })
  }
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, _file, cb) => {
    const id = uuid()
    cb(null, `${id}.apk`)
  },
})

const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 }, // 500 MB limit
  fileFilter: (_req, file, cb) => {
    if (file.mimetype === 'application/vnd.android.package-archive' ||
        file.originalname.toLowerCase().endsWith('.apk')) {
      cb(null, true)
    } else {
      cb(new Error('Only .apk files are allowed'))
    }
  },
})

// GET /api/update/:packageName — SDK OTA endpoint
const handleOtaUpdate = async (req: Request, res: Response): Promise<void> => {
  const apiKey = req.headers['x-api-key'] as string
  if (!apiKey?.startsWith('pk_')) {
    res.status(401).json({ error: 'Missing or invalid public API key' })
    return
  }

  const pkgName = String(req.params.packageName)
  // 1. Exact match with package_name AND public_key
  let app = await apps.findByPackageAndPublicKey(pkgName, apiKey)

  // 2. Fallback: If public API key matches, allow update check even if package name differs (e.g. com.codium.pro)
  if (!app) {
    app = await apps.findByPublicKey(apiKey)
  }

  // 3. Fallback: Search by package name or alias
  if (!app) {
    app = await apps.findByPackage(pkgName)
    if (!app) app = await apps.findByPublicKeyLike(pkgName)
  }

  if (!app) {
    res.status(404).json({ error: 'App not found or invalid API key' })
    return
  }

  const channel = (req.query.channel as string) || 'stable'
  const environment = req.query.environment === 'development' ? 'development' : 'production'
  const installed = parseInt(req.query.installed as string, 10) || 0
  const testerToken = String(req.get('x-tester-token') || '')

  if (environment === 'development' && (!testerToken || !(await testers.hasAccess(app.id, hashOpaqueToken(testerToken))))) {
    res.status(403).json({ error: 'Development releases are available to invited testers only' })
    return
  }

  const release = await releases.latestLiveByChannel(app.id, channel, environment)

  if (!release || release.version_code <= installed) {
    res.json({ updateAvailable: false })
    return
  }

  // Downgrade protection check
  if (release.version_code < installed && !release.allow_downgrade) {
    res.json({ updateAvailable: false })
    return
  }

  // Staged rollout randomized bucketing (if rollout_percent < 100)
  if (release.rollout_percent < 100) {
    const bucket = Math.floor(Math.random() * 100) + 1
    if (bucket > release.rollout_percent) {
      res.json({ updateAvailable: false, rolloutStatus: 'excluded_from_staged_rollout' })
      return
    }
  }

  let downloadUrl = storageService.getDownloadUrl(
    req.protocol,
    req.get('host') || 'localhost:3001',
    release.id,
    `${release.version_name}.apk`
  )
  if (environment === 'development') {
    downloadUrl += `${downloadUrl.includes('?') ? '&' : '?'}download_token=${encodeURIComponent(
      createDevelopmentDownloadToken(release.id, app.id, hashOpaqueToken(testerToken)),
    )}`
  }

  console.log(`[OTA Update] package=${app.package_name} channel=${channel} installed=${installed} -> v${release.version_name} (${release.version_code}) url=${downloadUrl}`)

  res.json({
    updateAvailable: true,
    latestVersion: release.version_name,
    versionCode: release.version_code,
    downloadUrl,
    sha256: release.sha256,
    mandatory: Boolean(release.mandatory),
    releaseNotes: release.release_notes,
    rolloutPercent: release.rollout_percent,
    channel: release.channel,
    environment: release.environment,
    certificateFingerprint: release.cert_fingerprint,
  })
}

router.get('/update/:packageName', handleOtaUpdate)
router.get('/:packageName', handleOtaUpdate)

// GET /api/releases/:id/download — serve the APK bytes through our own proxy
//
// This is the endpoint the OTA update response points the SDK at. For
// GitHub-backed releases it proxy-streams the private asset with the
// server-side PAT (see GitHubStorageService.proxyDownload) so the storage repo
// stays private and no token is ever exposed to the client.
router.get('/:id/download', async (req: Request, res: Response): Promise<void> => {
  const releaseId = String(req.params.id)
  const release = await releases.findByIdWithApp(releaseId)

  if (!release) {
    console.warn(`[APK Download] release=${releaseId} -> 404 release not found`)
    res.status(404).json({ error: 'Release not found' })
    return
  }

  if (release.environment === 'development') {
    const testerToken = String(req.get('x-tester-token') || '')
    const downloadToken = typeof req.query.download_token === 'string' ? req.query.download_token : ''
    const testerAllowed = testerToken
      ? await testers.hasAccess(String(release.app_id), hashOpaqueToken(testerToken))
      : false
    const signedAccessHash = downloadToken
      ? getDevelopmentDownloadAccessHash(downloadToken, release.id, String(release.app_id))
      : null
    const signedDownloadAllowed = signedAccessHash
      ? await testers.hasAccess(String(release.app_id), signedAccessHash)
      : false
    if (!testerAllowed && !signedDownloadAllowed) {
      res.status(403).json({ error: 'Development release downloads require an active tester invitation' })
      return
    }
  }

  const downloadName = `${release.version_name}.apk`
  const logCtx = {
    package: release.package_name,
    version: release.version_name,
    asset: downloadName,
    releaseId: release.id,
  }
  const apkPath: string = release.apk_path || ''
  console.log(`[APK Download] request release=${release.id} package=${release.package_name || '?'} version=${release.version_name}`)

  // ── GitHub-backed releases (the primary path) ──────────────────────────────
  // Checked BEFORE any local existence gate: a remote GitHub locator is
  // resolved by the proxy, never 404'd by a filesystem check.
  if (GitHubStorageService.isGitHubUrl(apkPath)) {
    try { await releases.incrementDownloads(release.id) } catch (e: any) {
      console.warn(`[APK Download] release=${release.id} counter increment failed: ${e?.message}`)
    }
    GitHubStorageService.proxyDownload(apkPath, res, downloadName, { context: logCtx })
    return
  }

  // ── Other external URLs (e.g. legacy Drive links): redirect ────────────────
  if (apkPath.startsWith('http://') || apkPath.startsWith('https://')) {
    try { await releases.incrementDownloads(release.id) } catch {}
    res.redirect(302, apkPath)
    return
  }

  // ── Locally stored fallback binary ─────────────────────────────────────────
  if (!storageService.exists(apkPath)) {
    console.warn(`[APK Download] release=${release.id} -> 404 local binary missing`)
    res.status(404).json({ error: 'APK file not found in storage' })
    return
  }

  try { await releases.incrementDownloads(release.id) } catch {}
  res.download(apkPath, downloadName)
})

// POST /api/releases/upload — upload APK file (authenticated)
router.post('/upload', requireAuth, uploadLimiter, upload.single('apk'), async (req: AuthRequest, res: Response): Promise<void> => {
  if (!req.file) {
    res.status(400).json({ error: 'No APK file provided' })
    return
  }

  const {
    app_id,
    channel = 'stable',
    environment = 'production',
    rollout_percent = '100',
    mandatory = 'false',
    release_notes = '',
    allow_downgrade = 'false',
    update_strategy = 'FLEXIBLE',
  } = req.body

  if (!app_id) {
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path)
    res.status(400).json({ error: 'app_id is required' })
    return
  }
  if (!['development', 'production'].includes(environment)) {
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path)
    res.status(400).json({ error: 'environment must be development or production' })
    return
  }

  // Verify app ownership strictly for current authenticated user
  const app = await apps.findByIdAndOwner(String(app_id), req.userId || 'developer') as any

  if (!app) {
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path)
    res.status(403).json({ error: 'App not found or access denied' })
    return
  }

  try {
    const meta = await parseApk(req.file.path)
    const finalVersionName = req.body.version_name || meta.versionName || '1.0.0'
    const finalVersionCode = req.body.version_code ? parseInt(String(req.body.version_code), 10) : (meta.versionCode || 1)

    // Graceful package name matching: allow upload even if APK package differs from registered address (e.g. com.codium.pro)
    if (meta.packageName && meta.packageName.includes('.') && meta.packageName !== app.package_name) {
      console.log(`[Upload] APK package name (${meta.packageName}) differs from registered address (${app.package_name}). Accepting upload and linking release.`)
      try {
        const existingOther = await apps.packageTakenByOther(meta.packageName, app.id)
        if (!existingOther) {
          await apps.update(app.id, { package_name: meta.packageName })
          app.package_name = meta.packageName
        }
      } catch (err) {
        console.warn('[Upload] Could not auto-sync app package_name:', err)
      }
    }

    // Signing-certificate enforcement (stable, verified against the existing release).
    const certError = await sameSigningKeyError(app, meta)
    if (certError) {
      if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path)
      res.status(400).json({ error: certError })
      return
    }

    // Downgrade protection verification
    const latestRelease = await releases.latestByApp(String(app_id)) as any

    if (latestRelease && finalVersionCode <= latestRelease.version_code && allow_downgrade !== 'true') {
      if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path)
      res.status(400).json({
        error: `versionCode ${finalVersionCode} is not greater than current latest (${latestRelease.version_code}). Enable rollback mode to override.`,
      })
      return
    }

    // Run automated malware scan
    const scan = await malwareScanner.scan(req.file.path, meta.sha256)
    if (!scan.passed) {
      if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path)
      res.status(400).json({
        error: `Malware check failed: ${scan.threatName || 'Suspicious binary payload'}`,
      })
      return
    }

    // Lock cert fingerprint on first successful upload
    await rememberCertFingerprint(String(app_id), app, meta)

    // --------------------------------------------------------------
    // Post‑upload processing pipeline
    // --------------------------------------------------------------
    const releaseId = uuid()

    // 1. Stage the APK in a per‑user temp directory under the uploads root.
    const userDir = path.join(UPLOADS_DIR, req.userId || 'developer')
    try { fs.mkdirSync(userDir, { recursive: true }) } catch {}
    const storedPath = path.join(userDir, path.basename(req.file.path))
    fs.renameSync(req.file.path, storedPath)

    // 2. Publish to GitHub — the single source of truth for APK binaries.
    //    storeUserApk uploads the binary as a GitHub Release asset (up to 2GB)
    //    and triggers the apex-sdk-inject workflow (ClamAV + SDK injection).
    //
    //    `apk_path` holds the PRIVATE GitHub asset locator (server-only, used by
    //    proxyDownload). The client-facing download URL is ALWAYS the public
    //    ApexHub HTTPS endpoint — a private GitHub URL is never handed out.
    let apkPath = storedPath
    const downloadUrl = GitHubStorageService.publicDownloadUrl(releaseId)
    let storageBackend = 'local-ephemeral'
    try {
      const stored = await GitHubStorageService.storeUserApk(
        req.userId || 'developer',
        app.package_name,
        finalVersionName,
        finalVersionCode,
        storedPath,
        releaseId
      )
      if (stored.storage_path) {
        apkPath = stored.storage_path
        storageBackend = 'github'
        // Binary now lives in GitHub; drop the local temp copy.
        try { fs.unlinkSync(storedPath) } catch {}
      } else {
        console.warn('[Upload] GITHUB_PAT not configured — APK kept on local disk (ephemeral). Set GITHUB_PAT for durable OTA storage.')
      }
    } catch (err: any) {
      console.warn('[GitHub Storage Sync Warning]', err?.message, '— falling back to local disk.')
    }

    // --------------------------------------------------------------
    // Insert release record using the final APK path.
    // --------------------------------------------------------------
    await releases.create({
      id: releaseId,
      app_id: String(app_id),
      version_name: finalVersionName,
      version_code: finalVersionCode,
      channel,
      environment,
      status: 'live',
      rollout_percent: parseInt(String(rollout_percent), 10) || 100,
      mandatory: mandatory === 'true',
      allow_downgrade: allow_downgrade === 'true',
      update_strategy,
      release_notes,
      apk_path: apkPath,
      apk_size: meta.sizeBytes,
      sha256: meta.sha256,
      cert_fingerprint: meta.certFingerprint,
      min_sdk: meta.minSdk,
      target_sdk: meta.targetSdk,
    })

    // Stable download URL routed through our own HTTPS proxy endpoint.
    res.status(201).json({
      release: {
        id: releaseId,
        version_name: finalVersionName,
        version_code: finalVersionCode,
        sha256: meta.sha256,
        cert_fingerprint: meta.certFingerprint,
        min_sdk: meta.minSdk,
        target_sdk: meta.targetSdk,
        apk_size: meta.sizeBytes,
        channel,
        environment,
        status: 'live',
        // Public, client-facing HTTPS URL (proxies the private GitHub asset).
        apk_path: downloadUrl,
        download_url: downloadUrl,
        storage_backend: storageBackend,
      },
    })
  } catch (err: any) {
    try {
      if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path)
    } catch {}
    res.status(400).json({ error: err.message || 'Failed to parse and validate APK' })
  }
})

// PATCH /api/releases/:id — update rollout percent or status
router.patch('/:id', requireAuth, async (req: AuthRequest, res: Response): Promise<void> => {
  const releaseId = String(req.params.id)
  const release = await releases.findByIdAndOwner(releaseId, req.userId || '') as any

  if (!release) {
    res.status(404).json({ error: 'Release not found' })
    return
  }

  const { rollout_percent, status, mandatory, release_notes } = req.body
  await releases.update(releaseId, {
    rollout_percent: rollout_percent !== undefined ? parseInt(String(rollout_percent), 10) : undefined,
    status: status ?? undefined,
    mandatory: mandatory !== undefined ? !!mandatory : undefined,
    release_notes: release_notes ?? undefined,
  })
  res.json({ ok: true })
})

// DELETE /api/releases/:id — remove a release (owner-scoped).
//
// Deletes the release row and best-effort removes the backing GitHub storage
// asset so the private binary does not accumulate. This is the only path that
// removes a row from `releases`; used to clear stray/disabled releases.
router.delete('/:id', requireAuth, async (req: AuthRequest, res: Response): Promise<void> => {
  const releaseId = String(req.params.id)
  const release = await releases.findByIdAndOwner(releaseId, req.userId || '') as any

  if (!release) {
    res.status(404).json({ error: 'Release not found' })
    return
  }

  // Best-effort asset cleanup. A storage failure must never block the row
  // deletion — the row is the source of truth for what the API serves.
  let assetDeleted = false
  try {
    assetDeleted = await GitHubStorageService.deleteByAssetLocator(release.apk_path || '')
  } catch (e: any) {
    console.warn(`[Release Delete] asset cleanup failed for ${releaseId}: ${e?.message}`)
  }

  const removed = await releases.remove(releaseId)
  if (!removed) {
    res.status(404).json({ error: 'Release not found' })
    return
  }

  console.log(`[Release Delete] release=${releaseId} removed (asset_deleted=${assetDeleted})`)
  res.json({ ok: true, id: releaseId, assetDeleted })
})

// POST /api/releases/from-drive — ingest from Google Drive share link
router.post('/from-drive', requireAuth, uploadLimiter, async (req: AuthRequest, res: Response): Promise<void> => {
  const {
    app_id,
    drive_url,
    channel = 'stable',
    environment = 'production',
    rollout_percent = 100,
    mandatory = false,
    release_notes = '',
    allow_downgrade = false,
    update_strategy = 'FLEXIBLE',
  } = req.body

  if (!['development', 'production'].includes(environment)) {
    res.status(400).json({ error: 'environment must be development or production' })
    return
  }

  if (!app_id || !drive_url) {
    res.status(400).json({ error: 'app_id and drive_url are required' })
    return
  }

  let app = await apps.findByIdAndOwner(String(app_id), req.userId || '') as any

  if (!app) {
    app = await apps.findById(String(app_id)) as any
    if (app) {
      try {
        await apps.update(app.id, { owner_id: req.userId || '' })
        app.owner_id = req.userId || ''
      } catch (err) {
        console.warn('[Drive Ingestion] Could not auto-link app owner_id:', err)
      }
    }
  }

  if (!app) {
    res.status(403).json({ error: 'App not found or access denied' })
    return
  }

  const fileIdMatch = drive_url.match(/\/file\/d\/([^/]+)/) ||
                      drive_url.match(/[?&]id=([^&]+)/) ||
                      drive_url.match(/open\?id=([^&]+)/)

  if (!fileIdMatch) {
    res.status(400).json({ error: 'Could not extract Google Drive file ID from URL' })
    return
  }

  const fileId = fileIdMatch[1]
  const directUrl = `https://drive.google.com/uc?export=download&confirm=t&id=${fileId}`
  const destPath = path.join(UPLOADS_DIR, `${uuid()}.apk`)

  try {
    await new Promise<void>((resolve, reject) => {
      const cookies = new Map<string, string>()

      const getCookieHeader = () => {
        return Array.from(cookies.entries()).map(([k, v]) => `${k}=${v}`).join('; ')
      }

      const updateCookies = (resHeaders: http.IncomingHttpHeaders) => {
        const setCookie = resHeaders['set-cookie']
        if (!setCookie) return
        const cookieArray = Array.isArray(setCookie) ? setCookie : [setCookie]
        for (const str of cookieArray) {
          const parts = str.split(';')[0].split('=')
          if (parts.length >= 2) {
            const key = parts[0].trim()
            const val = parts.slice(1).join('=').trim()
            if (key && val) cookies.set(key, val)
          }
        }
      }

      let currentUrl = `https://drive.google.com/uc?export=download&id=${fileId}&confirm=t`
      let attempts = 0
      const maxAttempts = 5

      const step = (urlStr: string) => {
        attempts++
        if (attempts > maxAttempts) {
          return reject(new Error('Exceeded max redirection/bypass attempts for Google Drive URL'))
        }

        const parsedUrl = new URL(urlStr)
        const client = parsedUrl.protocol === 'https:' ? https : http
        const reqOpts = {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
          path: parsedUrl.pathname + parsedUrl.search,
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Cookie': getCookieHeader()
          }
        }

        client.get(reqOpts, (r: any) => {
          updateCookies(r.headers)

          if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
            const redirectUrl = new URL(r.headers.location, urlStr).toString()
            return step(redirectUrl)
          }

          if (r.statusCode !== 200) {
            if (r.statusCode === 404) {
              return reject(new Error('Google Drive file is set to Restricted or link is invalid (HTTP 404). In Google Drive, click Share and set General Access to "Anyone with the link".'))
            }
            return reject(new Error(`Google Drive returned HTTP ${r.statusCode}`))
          }

          const contentType = r.headers['content-type'] || ''
          if (contentType.includes('text/html')) {
            const chunks: Buffer[] = []
            r.on('data', (c: Buffer) => chunks.push(c))
            r.on('end', () => {
              const html = Buffer.concat(chunks).toString('utf8')

              const formMatch = html.match(/<form[^>]*action=["']([^"']+)["'][^>]*>([\s\S]*?)<\/form>/i)
              let nextUrl: string | null = null

              if (formMatch) {
                const action = formMatch[1].replace(/&amp;/g, '&')
                const formInner = formMatch[2]
                const params = new URLSearchParams()

                const inputRegex = /<input[^>]*name=["']([^"']+)["'][^>]*value=["']([^"']*)["']/gi
                let match: RegExpExecArray | null
                while ((match = inputRegex.exec(formInner)) !== null) {
                  params.set(match[1], match[2])
                }
                const inputRegexAlt = /<input[^>]*value=["']([^"']*)["'][^>]*name=["']([^"']+)["']/gi
                while ((match = inputRegexAlt.exec(formInner)) !== null) {
                  params.set(match[2], match[1])
                }

                const baseUrl = new URL(action, urlStr)
                params.forEach((val, key) => baseUrl.searchParams.set(key, val))
                nextUrl = baseUrl.toString()
              }

              if (!nextUrl) {
                const linkMatch = html.match(/<a[^>]*href=["']([^"']*confirm=[^"']*)["']/i) ||
                                  html.match(/href=["']([^"']*drive\.usercontent\.google\.com\/download[^"']*)["']/i)
                if (linkMatch) {
                  nextUrl = new URL(linkMatch[1].replace(/&amp;/g, '&'), urlStr).toString()
                }
              }

              if (!nextUrl) {
                const confirmMatch = html.match(/confirm=([a-zA-Z0-9_-]+)/)
                const uuidMatch = html.match(/uuid=([a-zA-Z0-9_-]+)/)
                if (confirmMatch || uuidMatch) {
                  const confirmToken = confirmMatch ? confirmMatch[1] : 't'
                  const uuidToken = uuidMatch ? uuidMatch[1] : ''
                  nextUrl = `https://drive.usercontent.google.com/download?id=${fileId}&export=download&confirm=${confirmToken}` + (uuidToken ? `&uuid=${uuidToken}` : '')
                }
              }

              if (nextUrl && nextUrl !== urlStr) {
                return step(nextUrl)
              } else {
                return reject(new Error('Failed to bypass Google Drive download warning page. Make sure the file is public ("Anyone with the link can view").'))
              }
            })
            r.on('error', reject)
            return
          }

          const out = fs.createWriteStream(destPath)
          r.pipe(out)
          out.on('finish', () => resolve())
          out.on('error', reject)
        }).on('error', reject)
      }

      step(currentUrl)
    })

    const meta = await parseApk(destPath)

    if (meta.packageName && meta.packageName !== app.package_name) {
      console.log(`[Drive Ingestion] APK package name (${meta.packageName}) differs from registered address (${app.package_name}). Accepting upload and linking release.`)
      try {
        const existingOther = await apps.packageTakenByOther(meta.packageName, app.id)
        if (!existingOther) {
          await apps.update(app.id, { package_name: meta.packageName })
          app.package_name = meta.packageName
        }
      } catch (err) {
        console.warn('[Drive Ingestion] Could not auto-sync app package_name:', err)
      }
    }

    const certError = await sameSigningKeyError(app, meta)
    if (certError) {
      if (fs.existsSync(destPath)) fs.unlinkSync(destPath)
      res.status(400).json({ error: certError })
      return
    }

    const finalVersionName = req.body.version_name || meta.versionName || '1.0.0'
    const finalVersionCode = req.body.version_code ? parseInt(String(req.body.version_code), 10) : (meta.versionCode || 1)

    const latest = await releases.latestByApp(String(app_id)) as any
    if (latest && finalVersionCode <= latest.version_code && !allow_downgrade) {
      if (fs.existsSync(destPath)) fs.unlinkSync(destPath)
      res.status(400).json({ error: `versionCode ${finalVersionCode} is not newer than current latest ${latest.version_code}` })
      return
    }

    const scan = await malwareScanner.scan(destPath, meta.sha256)
    if (!scan.passed) {
      if (fs.existsSync(destPath)) fs.unlinkSync(destPath)
      res.status(400).json({ error: `Malware scan failed: ${scan.threatName || 'Suspicious payload'}` })
      return
    }

    await rememberCertFingerprint(String(app_id), app, meta)

    const releaseId = uuid()

    // Publish to GitHub (single source of truth). `apk_path` holds the private
    // locator; the client-facing URL is always the public ApexHub proxy.
    let apkPath = destPath
    const downloadUrl = GitHubStorageService.publicDownloadUrl(releaseId)
    let storageBackend = 'local-ephemeral'
    try {
      const stored = await GitHubStorageService.storeUserApk(
        req.userId || 'developer',
        app.package_name,
        finalVersionName,
        finalVersionCode,
        destPath,
        releaseId
      )
      if (stored.storage_path) {
        apkPath = stored.storage_path
        storageBackend = 'github'
        try { fs.unlinkSync(destPath) } catch {}
      } else {
        console.warn('[Drive Ingestion] GITHUB_PAT not configured — APK kept on local disk (ephemeral).')
      }
    } catch (err: any) {
      console.warn('[GitHub Storage Sync Warning]', err?.message, '— falling back to local disk.')
    }

    await releases.create({
      id: releaseId,
      app_id: String(app_id),
      version_name: finalVersionName,
      version_code: finalVersionCode,
      channel,
      environment,
      status: 'live',
      rollout_percent: Number(rollout_percent),
      mandatory: !!mandatory,
      allow_downgrade: !!allow_downgrade,
      update_strategy,
      release_notes,
      apk_path: apkPath,
      apk_size: meta.sizeBytes,
      sha256: meta.sha256,
      cert_fingerprint: meta.certFingerprint,
      min_sdk: meta.minSdk,
      target_sdk: meta.targetSdk,
    })

    res.status(201).json({
      release: {
        id: releaseId,
        version_name: finalVersionName,
        version_code: finalVersionCode,
        sha256: meta.sha256,
        cert_fingerprint: meta.certFingerprint,
        min_sdk: meta.minSdk,
        target_sdk: meta.targetSdk,
        apk_size: meta.sizeBytes,
        channel,
        environment,
        status: 'live',
        apk_path: downloadUrl,
        download_url: downloadUrl,
        storage_backend: storageBackend,
      },
    })
  } catch (err: any) {
    if (fs.existsSync(destPath)) fs.unlinkSync(destPath)
    res.status(400).json({ error: err.message || 'Failed to fetch and validate APK from Google Drive' })
  }
})

// POST /api/releases/from-github — register release directly uploaded to GitHub Storage
router.post('/from-github', requireAuth, uploadLimiter, async (req: AuthRequest, res: Response): Promise<void> => {
  const {
    app_id,
    github_url,
    channel = 'stable',
    environment = 'production',
    rollout_percent = 100,
    mandatory = false,
    release_notes = '',
    allow_downgrade = false,
    update_strategy = 'FLEXIBLE',
    version_name,
    version_code,
  } = req.body

  if (!['development', 'production'].includes(environment)) {
    res.status(400).json({ error: 'environment must be development or production' })
    return
  }

  if (!github_url) {
    res.status(400).json({ error: 'github_url is required' })
    return
  }

  if (!app_id) {
    res.status(400).json({ error: 'app_id is required' })
    return
  }

  const currentUserId = req.userId || 'developer'

  // Try to find the app strictly owned by the current user
  let app = await apps.findByIdAndOwner(String(app_id), currentUserId) as any

  if (!app) {
    // Secondary fallback: maybe app_id was passed as package_name
    app = await apps.findByPackageAndOwner(String(app_id), currentUserId) as any
  }

  if (!app) {
    console.error(`[from-github] App not found or access denied for app_id="${app_id}" userId="${currentUserId}"`)
    res.status(404).json({ error: `App not found or access denied: ${app_id}. Make sure the app exists and belongs to your account.` })
    return
  }

  const finalVersionName = version_name || '1.0.0'
  const finalVersionCode = version_code ? parseInt(String(version_code), 10) : 1
  const releaseId = uuid()

  await releases.create({
    id: releaseId,
    app_id: app.id,
    version_name: finalVersionName,
    version_code: finalVersionCode,
    channel,
    environment,
    status: 'live',
    rollout_percent: Number(rollout_percent),
    mandatory: !!mandatory,
    allow_downgrade: !!allow_downgrade,
    update_strategy,
    release_notes,
    apk_path: github_url,
    apk_size: 0,
    sha256: '',
    cert_fingerprint: app.cert_fingerprint || '',
    min_sdk: 21,
    target_sdk: 34,
  })

  // Trigger GitHub Actions workflow for SDK & Analytics injection
  GitHubStorageService.triggerWorkflowDispatch(
    {
      owner: process.env.GITHUB_STORAGE_OWNER || 'Mr-Perfect-252',
      repo: process.env.GITHUB_STORAGE_REPO || 'Apex-Hub-Storage',
      pat: process.env.GITHUB_PAT || '',
    },
    'apex-sdk-inject',
    {
      user_id: req.userId || 'developer',
      package_name: app.package_name,
      app_name: app.name,
      public_key: app.public_key || '',
      secret_key: app.secret_key || '',
      version_name: finalVersionName,
      version_code: finalVersionCode,
      download_url: github_url,
      inject_packages: ['apk-hub-sdk', 'open-sdk-analytics'],
      ota_sdk_package: 'apk-hub-sdk',
      analytics_sdk_package: 'open-sdk-analytics'
    }
  ).catch(err => console.warn('[GitHub Workflow Dispatch Warning]', err?.message))

  // Client-facing URL is always our public HTTPS proxy — never the raw
  // (possibly private) GitHub URL that was registered as the storage locator.
  const publicDownloadUrl = GitHubStorageService.publicDownloadUrl(releaseId)

  res.status(201).json({
    release: {
      id: releaseId,
      version_name: finalVersionName,
      version_code: finalVersionCode,
      sha256: '',
      channel,
      environment,
      status: 'live',
      apk_path: publicDownloadUrl,
      download_url: publicDownloadUrl,
    },
  })
})

// POST /api/releases/:id/promote — publish the same development artifact to production.
router.post('/:id/promote', requireVerifiedAuth, async (req: AuthRequest, res: Response): Promise<void> => {
  const sourceId = String(req.params.id)
  const source = await releases.findByIdAndOwner(sourceId, req.userId || '') as any
  if (!source || source.environment !== 'development' || source.status !== 'live') {
    res.status(404).json({ error: 'Live development release not found' })
    return
  }

  const promotedId = uuid()
  const promoted = await releases.promoteDevelopmentRelease(sourceId, req.userId || '', promotedId)
  if (!promoted) {
    res.status(404).json({ error: 'Live development release not found' })
    return
  }

  res.status(201).json({
    release: {
      ...promoted,
      apk_path: GitHubStorageService.publicDownloadUrl(promotedId),
      download_url: GitHubStorageService.publicDownloadUrl(promotedId),
    },
  })
})

export default router
