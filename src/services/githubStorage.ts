import https from 'https'
import http from 'http'
import fs from 'fs'
import type { ServerResponse } from 'http'

export interface GitHubConfig {
  pat: string
  owner: string
  repo: string
  branch?: string
}

/** Context emitted in download logs. Never contains credentials. */
export interface DownloadLogContext {
  package?: string
  version?: string
  asset?: string
  releaseId?: string
}

/** Hosts that accept a GitHub `Authorization` header. */
// GitHub's auth-accepting endpoints. NOTE: the signed redirect target
// (objects.githubusercontent.com / *.githubusercontent.com CDN) must NOT
// receive the Authorization header — pre-signed URLs reject "double auth"
// (400 "Only one auth mechanism allowed"). Only raw.githubusercontent.com
// serves private content with a token, so it stays in the allow-list.
const GITHUB_AUTH_HOSTS = /^(api\.github\.com|github\.com|uploads\.github\.com|raw\.githubusercontent\.com)$/i

/**
 * GitHub-backed APK storage.
 *
 * APK binaries are stored as **GitHub Release assets** (not via the Contents
 * API), which supports files up to 2 GB — matching the platform's large-APK
 * needs. Each (user, package) gets one release container; each version is a
 * distinct asset. Downloads are proxy-streamed server-side with the PAT so the
 * storage repo can be private and the token is never exposed to clients.
 */
export class GitHubStorageService {
  private static getDefaultConfig(): GitHubConfig {
    return {
      owner: process.env.GITHUB_STORAGE_OWNER || 'Mr-Perfect-252',
      repo: process.env.GITHUB_STORAGE_REPO || 'Apex-Hub-Storage',
      pat: process.env.GITHUB_PAT || process.env.GITHUB_TOKEN || '',
      branch: process.env.GITHUB_BRANCH || 'main'
    }
  }

  /**
   * Public accessor for the resolved storage config. Used by callers that need
   * to pass the config to `uploadFile` (e.g. App manifest sync).
   */
  static getConfig(): GitHubConfig {
    return this.getDefaultConfig()
  }

  /** True when a stored apk_path points at our GitHub storage backend. */
  static isGitHubUrl(url: string): boolean {
    return /^https?:\/\/(api\.github\.com|uploads\.github\.com|github\.com|.*\.githubusercontent\.com)\//i.test(url)
  }

  /**
   * Best-effort delete of a stored APK asset given the private `apk_path`
   * locator persisted on a release
   * (`https://api.github.com/repos/{owner}/{repo}/releases/assets/{id}`).
   *
   * Used when a release row is removed so the binary does not accumulate in the
   * private storage repo. Never throws: a missing asset (404) or an unconfigured
   * PAT is not an error for the caller — the row deletion is what matters.
   * Returns true when the asset was actually deleted.
   */
  static async deleteByAssetLocator(apkPath: string): Promise<boolean> {
    if (!apkPath || !this.isGitHubUrl(apkPath)) return false
    const match = apkPath.match(/\/repos\/([^/]+)\/([^/]+)\/releases\/assets\/(\d+)/i)
    if (!match) return false
    const config = this.getDefaultConfig()
    if (!config.pat) {
      console.log('[GitHub Storage] deleteByAssetLocator: no PAT configured, skipping remote delete.')
      return false
    }
    const [, owner, repo, assetId] = match
    try {
      await this.makeGitHubRequest('DELETE', `/repos/${owner}/${repo}/releases/assets/${assetId}`, config.pat)
      return true
    } catch (err: any) {
      console.warn(`[GitHub Storage] deleteByAssetLocator asset=${assetId} failed: ${err?.message || err}`)
      return false
    }
  }

  /**
   * Canonical public base URL for client-facing download links. Always HTTPS —
   * Android blocks cleartext traffic, so the OTA URL must never be http://.
   *
   * Precedence: PUBLIC_BASE_URL → PUBLIC_DOWNLOAD_BASE_URL → Vercel URLs →
   * the production ApexHub domain.
   */
  static getPublicBaseUrl(): string {
    const configured = (process.env.PUBLIC_BASE_URL || process.env.PUBLIC_DOWNLOAD_BASE_URL || '').trim()
    const raw = configured
      || (process.env.VERCEL_PROJECT_PRODUCTION_URL || process.env.VERCEL_URL || '').trim()
      || 'apex-hub-production.vercel.app'

    let base = raw.replace(/\/+$/, '')
    if (!/^https?:\/\//i.test(base)) base = `https://${base}`
    // Force HTTPS: a cleartext download URL would be blocked on-device.
    base = base.replace(/^http:\/\//i, 'https://')
    return base
  }

  /**
   * The public, client-facing OTA download endpoint for a release. This is the
   * ONLY download URL ever handed to clients/SDKs — never a private GitHub URL.
   */
  static publicDownloadUrl(releaseId: string): string {
    return `${this.getPublicBaseUrl()}/api/releases/${releaseId}/download`
  }

  private static sanitizeTag(s: string): string {
    return s.replace(/[^A-Za-z0-9._-]/g, '_')
  }

  /** Strips characters that could break out of a Content-Disposition header. */
  private static sanitizeFilename(name: string): string {
    return (name || 'release.apk').replace(/[\r\n"\\/]/g, '_')
  }

  /**
   * Publish an APK as a GitHub Release asset (up to 2 GB).
   *
   * Returns two distinct things on purpose:
   *  - `storage_path` — the **private** GitHub asset API locator. Persisted to
   *    `releases.apk_path` and resolved server-side by `proxyDownload`; it is
   *    never sent to a client.
   *  - `download_url` — the **public** ApexHub HTTPS proxy endpoint the SDK
   *    downloads from.
   *
   * Also triggers the apex-sdk-inject workflow (ClamAV + SDK injection).
   */
  static async storeUserApk(
    userId: string,
    packageName: string,
    versionName: string,
    versionCode: number,
    localApkPath: string,
    releaseId?: string
  ): Promise<{ sha: string; download_url: string; storage_path: string; path: string }> {
    const config = this.getDefaultConfig()
    if (!config.pat) {
      console.log('[GitHub Storage] GITHUB_PAT not set, skipping remote publish.')
      return { sha: '', download_url: '', storage_path: '', path: '' }
    }

    const tag = this.sanitizeTag(`apk-${userId}-${packageName}`)
    const assetName = this.sanitizeTag(`v${versionName}_${versionCode}.apk`)
    const relPath = `users/${userId}/apps/${packageName}/${assetName}`

    // 1. Ensure the release container exists for this app.
    const release = await this.ensureRelease(config, tag, packageName, userId)

    // 2. Remove any existing asset with the same name (re-upload of same version).
    await this.deleteAssetIfExists(config, release.assets || [], assetName)

    // 3. Upload the binary as a release asset via uploads.github.com (2 GB max).
    const stat = fs.statSync(localApkPath)
    const asset = await this.uploadReleaseAsset(config, release.id, assetName, localApkPath, stat.size)

    // Internal, authenticated asset API locator — works for private repos when
    // fetched with Accept: application/octet-stream + PAT (see proxyDownload).
    const storagePath = `https://api.github.com/repos/${config.owner}/${config.repo}/releases/assets/${asset.id}`

    // The client-facing URL is always our own HTTPS proxy endpoint.
    const publicUrl = releaseId ? this.publicDownloadUrl(releaseId) : ''

    // 4. Fire-and-forget SDK injection workflow.
    this.triggerWorkflowDispatch(config, 'apex-sdk-inject', {
      user_id: userId,
      package_name: packageName,
      version_name: versionName,
      version_code: versionCode,
      apk_path: relPath,
      // The workflow runs server-side with the PAT: give it the private asset
      // locator, not the client-facing proxy URL.
      download_url: storagePath,
      inject_packages: ['apk-hub-sdk', 'open-sdk-analytics'],
      ota_sdk_package: 'apk-hub-sdk',
      analytics_sdk_package: 'open-sdk-analytics'
    }).catch(err => console.warn('[GitHub Dispatch Warning]', err?.message))

    return { sha: String(asset.id), download_url: publicUrl, storage_path: storagePath, path: relPath }
  }

  /**
   * Commits (creates or updates) a small file in the storage repo via the
   * GitHub **Contents API**. Used for manifest sync (e.g. `app.json`) — plain
   * metadata blobs, not APK binaries (those go through `storeUserApk` as
   * Release assets, which supports 2 GB files the Contents API cannot).
   */
  static async uploadFile(
    config: GitHubConfig,
    filePath: string,
    contentBuffer: Buffer,
    commitMessage: string
  ): Promise<{ sha: string; download_url: string }> {
    const { pat, owner, repo, branch = 'main' } = config
    const pathUrl = `/repos/${owner}/${repo}/contents/${filePath}`
    let existingSha: string | undefined
    try {
      const existing = await this.makeGitHubRequest('GET', pathUrl, pat, undefined, branch)
      if (existing && existing.sha) existingSha = existing.sha
    } catch {
      // File does not exist yet — a create, not an update.
    }

    const payload: Record<string, any> = {
      message: commitMessage,
      content: contentBuffer.toString('base64'),
      branch
    }
    if (existingSha) payload.sha = existingSha

    const response = await this.makeGitHubRequest('PUT', pathUrl, pat, payload)
    return {
      sha: response?.content?.sha || '',
      download_url:
        response?.content?.download_url ||
        `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`
    }
  }

  /**
   * Classifies a non-200 response from the storage backend into a client-facing
   * status + message. Crucially, a GitHub auth/config problem is surfaced as a
   * **server error** (5xx), never silently as an Android-side 404.
   */
  static classifyStorageFailure(
    host: string,
    status: number,
    patPresent: boolean
  ): { status: number; message: string; serverError: boolean } {
    const isGitHub = /(^|\.)github(usercontent|assets)?\.com$/i.test(host)
    if (isGitHub && !patPresent) {
      return {
        status: 503,
        message: 'APK storage is not configured (GITHUB_PAT missing) — server-side.',
        serverError: true
      }
    }
    if (isGitHub && (status === 401 || status === 403)) {
      return {
        status: 502,
        message: 'APK storage authentication failed (check GITHUB_PAT scope) — server-side.',
        serverError: true
      }
    }
    if (status >= 500) {
      return { status: 502, message: `APK storage responded HTTP ${status}`, serverError: true }
    }
    if (status === 404) {
      return { status: 404, message: 'APK asset not found in storage', serverError: false }
    }
    return { status: status || 502, message: `APK storage responded HTTP ${status}`, serverError: status >= 400 && status >= 500 }
  }

  /**
   * Proxy-streams a GitHub-hosted binary to the client using the server-side
   * PAT. Works for private storage repos; the token is never exposed. Follows
   * the signed redirect GitHub issues for asset downloads (dropping the
   * Authorization header at the pre-signed CDN hop).
   */
  static proxyDownload(
    fileUrl: string,
    res: ServerResponse,
    downloadName: string,
    opts: { redirectsLeft?: number; context?: DownloadLogContext } = {}
  ): void {
    const redirectsLeft = opts.redirectsLeft ?? 5
    const ctx = opts.context || {}
    const label = `package=${ctx.package || '?'} version=${ctx.version || '?'} asset=${ctx.asset || '?'} release=${ctx.releaseId || '?'}`
    const safeName = this.sanitizeFilename(downloadName)

    if (redirectsLeft < 0) {
      console.warn(`[APK Download] ${label} -> too many redirects`)
      if (!res.headersSent) { res.statusCode = 508; res.end('Too many redirects') }
      return
    }

    let parsed: URL
    try { parsed = new URL(fileUrl) } catch {
      console.warn(`[APK Download] ${label} -> invalid storage URL`)
      if (!res.headersSent) { res.statusCode = 400; res.end('Invalid storage URL') }
      return
    }

    const pat = this.getDefaultConfig().pat
    const attachAuth = GITHUB_AUTH_HOSTS.test(parsed.hostname) && !!pat
    const headers: Record<string, string> = {
      'User-Agent': 'ApexHub-Platform/1.0',
      // octet-stream tells the asset API to return the binary (via redirect)
      // rather than JSON metadata.
      'Accept': 'application/octet-stream'
    }
    // NEVER log the PAT or the headers object.
    if (attachAuth) headers['Authorization'] = `token ${pat}`

    // Follow the URL's own scheme + port (GitHub is https:443, but honoring the
    // parsed values keeps the proxy correct for any configured storage host).
    const client = parsed.protocol === 'http:' ? http : https
    const port = parsed.port ? Number(parsed.port) : undefined

    client.get({ hostname: parsed.hostname, port, path: parsed.pathname + parsed.search, headers }, upstream => {
      const status = upstream.statusCode || 0
      console.log(`[APK Download] ${label} -> host=${parsed.hostname} githubStatus=${status}`)

      if (status >= 300 && status < 400 && upstream.headers.location) {
        const next = new URL(upstream.headers.location, fileUrl).toString()
        upstream.resume()
        return this.proxyDownload(next, res, downloadName, { redirectsLeft: redirectsLeft - 1, context: ctx })
      }

      if (status !== 200) {
        upstream.resume()
        const failure = this.classifyStorageFailure(parsed.hostname, status, !!pat)
        console.warn(`[APK Download] ${label} -> ${failure.serverError ? 'SERVER ERROR' : 'client error'} ${failure.status}: ${failure.message}`)
        if (!res.headersSent) { res.statusCode = failure.status; res.end(failure.message) }
        return
      }

      res.statusCode = 200
      res.setHeader('Content-Type', 'application/vnd.android.package-archive')
      res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`)
      if (upstream.headers['content-length']) res.setHeader('Content-Length', upstream.headers['content-length'] as string)
      res.setHeader('Cache-Control', 'no-store')
      upstream.pipe(res)
    }).on('error', err => {
      console.warn(`[APK Download] ${label} -> upstream error: ${err.message}`)
      if (!res.headersSent) { res.statusCode = 502; res.end(`Storage fetch failed: ${err.message}`) }
    })
  }

  /** Triggers a repository_dispatch event (GitHub Actions). */
  static async triggerWorkflowDispatch(
    config: GitHubConfig,
    eventType: string,
    clientPayload: Record<string, any>
  ): Promise<boolean> {
    try {
      await this.makeGitHubRequest('POST', `/repos/${config.owner}/${config.repo}/dispatches`, config.pat, {
        event_type: eventType,
        client_payload: clientPayload
      })
      return true
    } catch (err: any) {
      console.warn(`[GitHub Dispatch Warning] ${err?.message || err}`)
      return false
    }
  }

  /** Get the release for `tag`, creating it if it doesn't exist. */
  private static async ensureRelease(config: GitHubConfig, tag: string, packageName: string, userId: string): Promise<any> {
    const { owner, repo, pat } = config
    try {
      return await this.makeGitHubRequest('GET', `/repos/${owner}/${repo}/releases/tags/${tag}`, pat)
    } catch {
      // Not found — create it.
    }
    return this.makeGitHubRequest('POST', `/repos/${owner}/${repo}/releases`, pat, {
      tag_name: tag,
      name: `APK storage — ${packageName}`,
      body: `Universal APK storage container for user ${userId}.`,
      draft: false,
      prerelease: false
    })
  }

  private static async deleteAssetIfExists(config: GitHubConfig, assets: any[], assetName: string): Promise<void> {
    const existing = assets.find(a => a?.name === assetName)
    if (!existing) return
    try {
      await this.makeGitHubRequest('DELETE', `/repos/${config.owner}/${config.repo}/releases/assets/${existing.id}`, config.pat)
    } catch (err: any) {
      console.warn('[GitHub Storage] failed to delete existing asset:', err?.message)
    }
  }

  /** Streams a local file to uploads.github.com as a release asset (up to 2 GB). */
  private static uploadReleaseAsset(
    config: GitHubConfig,
    releaseId: number,
    assetName: string,
    localApkPath: string,
    contentLength: number
  ): Promise<{ id: number; browser_download_url: string }> {
    const { owner, repo, pat } = config
    return new Promise((resolve, reject) => {
      const req = https.request({
        hostname: 'uploads.github.com',
        path: `/repos/${owner}/${repo}/releases/${releaseId}/assets?name=${encodeURIComponent(assetName)}`,
        method: 'POST',
        headers: {
          'User-Agent': 'ApexHub-Platform/1.0',
          'Authorization': `token ${pat}`,
          'Accept': 'application/vnd.github+json',
          'Content-Type': 'application/vnd.android.package-archive',
          'Content-Length': contentLength
        }
      }, res => {
        const chunks: Buffer[] = []
        res.on('data', c => chunks.push(c))
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8')
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try { resolve(JSON.parse(text)) } catch { reject(new Error('Bad asset upload response')) }
          } else {
            reject(new Error(`Asset upload HTTP ${res.statusCode}: ${text.slice(0, 200)}`))
          }
        })
      })
      req.on('error', reject)
      fs.createReadStream(localApkPath).on('error', reject).pipe(req)
    })
  }

  private static makeGitHubRequest(method: string, pathUrl: string, pat: string, body?: any, branch?: string): Promise<any> {
    return new Promise((resolve, reject) => {
      let finalPath = pathUrl
      // Contents API reads need an explicit ref so we read the target branch.
      if (branch && method === 'GET') finalPath += `?ref=${encodeURIComponent(branch)}`

      const postData = body ? JSON.stringify(body) : ''
      const req = https.request({
        hostname: 'api.github.com',
        path: finalPath,
        method,
        headers: {
          'User-Agent': 'ApexHub-Platform/1.0',
          'Authorization': `token ${pat}`,
          'Accept': 'application/vnd.github+json',
          'Content-Type': 'application/json',
          ...(body ? { 'Content-Length': Buffer.byteLength(postData) } : {})
        }
      }, (res) => {
        const chunks: Buffer[] = []
        res.on('data', c => chunks.push(c))
        res.on('end', () => {
          const resText = Buffer.concat(chunks).toString('utf8')
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            try { resolve(resText ? JSON.parse(resText) : {}) } catch { resolve({}) }
          } else {
            reject(new Error(`GitHub API HTTP ${res.statusCode}: ${resText.slice(0, 200)}`))
          }
        })
      })
      req.on('error', reject)
      if (postData) req.write(postData)
      req.end()
    })
  }
}
