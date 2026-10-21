/**
 * ApexHub OTA APK download flow — end-to-end local verification.
 *
 * Boots the REAL express app (routes, download endpoint, proxy) with a mocked
 * store and a stubbed GitHub upstream, then asserts the OTA chain:
 *
 *   update API -> ApexHub HTTPS download URL -> download endpoint
 *     -> proxyDownload (private GitHub asset) -> APK bytes
 *
 * Run:  node dist/tests/otaDownload.test.js   (after `tsc`)
 */
import http from 'http'
import https from 'https'
import { Writable, Readable } from 'stream'
import assert from 'assert'

// Must be set before requiring the app so index.ts doesn't start a listener.
process.env.VERCEL = '1'
process.env.GITHUB_STORAGE_OWNER = 'Mr-Perfect-252'
process.env.GITHUB_STORAGE_REPO = 'Apex-Hub-Storage'
process.env.PUBLIC_BASE_URL = 'https://apex-hub-production.vercel.app'

const { GitHubStorageService } = require('../services/githubStorage')
const { storageService } = require('../services/storage/storageService')
const { createDevelopmentDownloadToken, hashOpaqueToken } = require('../services/testerAccess')
const store = require('../store')

let passed = 0
let failed = 0
function check(name: string, fn: () => void | Promise<void>) {
  return (async () => {
    try {
      await fn()
      console.log(`  \u2714 ${name}`)
      passed++
    } catch (err: any) {
      console.error(`  \u2718 ${name}\n      ${err?.message || err}`)
      failed++
    }
  })()
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────
function request(base: string, path: string, headers: Record<string, string> = {}): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = http.get(base + path, { headers }, res => {
      const chunks: Buffer[] = []
      res.on('data', c => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode || 0, headers: res.headers, body: Buffer.concat(chunks) }))
    })
    req.on('error', reject)
  })
}

/** Minimal ServerResponse stand-in that captures piped bytes. */
class MockRes extends Writable {
  statusCode = 200
  headers: Record<string, string> = {}
  headersSent = false
  body = Buffer.alloc(0)
  setHeader(k: string, v: any) { this.headers[k.toLowerCase()] = String(v); this.headersSent = true }
  removeHeader() {}
  end(chunk?: any) {
    if (chunk) this.body = Buffer.concat([this.body, Buffer.from(chunk as any)])
    this.headersSent = true
    super.end()
    return this
  }
  _write(chunk: any, _enc: any, cb: any) { this.body = Buffer.concat([this.body, Buffer.from(chunk)]); cb() }
}

function mockUpstream(statusCode: number, headers: Record<string, string>, body?: string): any {
  const r: any = new Readable({ read() {} })
  if (body) r.push(Buffer.from(body))
  r.push(null)
  r.statusCode = statusCode
  r.headers = headers
  return r
}

/** Stub https.get for a map of hostname -> MockRes-like responder. */
function stubHttpsGet(responder: (opts: any) => any) {
  const seen: Array<{ hostname: string; headers: Record<string, string> }> = []
  const orig = https.get
  ;(https as any).get = (opts: any, cb: any) => {
    seen.push({ hostname: opts.hostname, headers: opts.headers || {} })
    const r = responder(opts)
    const req: any = new Readable({ read() {} }); req.push(null)
    req.end = () => {}; req.write = () => {}
    process.nextTick(() => cb(mockUpstream(r.statusCode, r.headers, r.body)))
    return req
  }
  return { seen, restore: () => { (https as any).get = orig } }
}

/** Stub https.request (used by makeGitHubRequest / uploadFile). */
function stubHttpsRequest(responder: (opts: any) => any) {
  const seen: Array<{ method: string; path: string; headers: Record<string, string> }> = []
  const orig = https.request
  ;(https as any).request = (opts: any, cb: any) => {
    seen.push({ method: opts.method || 'GET', path: opts.path || '', headers: opts.headers || {} })
    const r = responder(opts)
    const req: any = new Readable({ read() {} }); req.push(null)
    req.write = () => {}; req.end = () => { process.nextTick(() => cb(mockUpstream(r.statusCode, r.headers, r.body))) }
    return req
  }
  return { seen, restore: () => { (https as any).request = orig } }
}

// ── Store mocks ──────────────────────────────────────────────────────────────
function setRelease(rel: any) { (store.releases as any).findByIdWithApp = async () => rel }
function setApp(app: any) { (store.apps as any).findByPackageAndPublicKey = async () => app }
function setLatestRelease(rel: any) { (store.releases as any).latestLiveByChannel = async () => rel }
;(store.releases as any).incrementDownloads = async () => {}

const FAKE_APK = Buffer.from('PK\u0003\u0004 FAKE APK BYTES FOR OTA TEST')
const GH_ASSET = 'https://api.github.com/repos/Mr-Perfect-252/Apex-Hub-Storage/releases/assets/42'

async function main() {
  console.log('\n\u{1F680} ApexHub OTA APK download flow — local verification\n')

  // ── 1. URL builders ────────────────────────────────────────────────────────
  await check('storageService.getDownloadUrl returns HTTPS production proxy URL', () => {
    const url = storageService.getDownloadUrl('http', 'evil.example.com', 'rel-123', 'app.apk')
    assert(url.startsWith('https://'), `expected https, got ${url}`)
    assert(url.includes('apex-hub-production.vercel.app'), `wrong host: ${url}`)
    assert(url === 'https://apex-hub-production.vercel.app/api/releases/rel-123/download', `unexpected: ${url}`)
    assert(!/api\.github\.com/.test(url), 'must not point at api.github.com')
  })

  await check('GitHubStorageService exposes uploadFile (Contents API)', () => {
    assert.strictEqual(typeof GitHubStorageService.uploadFile, 'function', 'uploadFile missing')
    assert.strictEqual(typeof GitHubStorageService.getConfig, 'function', 'getConfig missing')
  })

  await check('uploadFile commits via Contents API using the PAT', async () => {
    const cfg = { owner: 'o', repo: 'r', pat: 'tok', branch: 'main' }
    const stub = stubHttpsRequest(opts => {
      if ((opts.method || 'GET') === 'GET') return { statusCode: 404, headers: {} }
      return { statusCode: 201, headers: {}, body: JSON.stringify({ content: { sha: 'abc', download_url: 'https://raw.githubusercontent.com/o/r/main/x.json' } }) }
    })
    try {
      const res = await GitHubStorageService.uploadFile(cfg, 'users/u/apps/p/app.json', Buffer.from('{}'), 'msg')
      assert.strictEqual(res.sha, 'abc')
      assert(stub.seen.every(s => s.headers['Authorization'] === 'token tok'), 'PAT not attached to GitHub request')
      assert(stub.seen.some(s => s.method === 'PUT'), 'expected a PUT (commit) request')
      assert(stub.seen.some(s => s.method === 'GET' && s.path.includes('?ref=main')), 'expected a GET lookup with ref')
    } finally { stub.restore() }
  })

  // ── 2. classifyStorageFailure unit cases ───────────────────────────────────
  await check('classifyStorageFailure maps GitHub auth failure to 5xx', () => {
    const a = GitHubStorageService.classifyStorageFailure('api.github.com', 403, true)
    assert(a.serverError && a.status === 502, `expected 502 server error, got ${JSON.stringify(a)}`)
    const b = GitHubStorageService.classifyStorageFailure('api.github.com', 404, false)
    assert(b.serverError && b.status === 503, `expected 503 for missing PAT, got ${JSON.stringify(b)}`)
    const c = GitHubStorageService.classifyStorageFailure('api.github.com', 404, true)
    assert(!c.serverError && c.status === 404, `expected 404 for genuinely missing asset, got ${JSON.stringify(c)}`)
    const d = GitHubStorageService.classifyStorageFailure('raw.githubusercontent.com', 401, true)
    assert(d.serverError, 'githubusercontent 401 should be a server error')
  })

  // ── 3. proxyDownload against a REAL local upstream (redirects + bytes) ─────
  await check('proxyDownload follows redirects and streams APK bytes', async () => {
    const srv = http.createServer((req, res) => {
      if (req.url === '/asset') { res.writeHead(302, { Location: '/signed' }); res.end() }
      else if (req.url === '/signed') { res.writeHead(200, { 'Content-Length': String(FAKE_APK.length) }); res.end(FAKE_APK) }
      else if (req.url === '/denied') { res.writeHead(403); res.end('nope') }
      else { res.writeHead(404); res.end('missing') }
    })
    await new Promise<void>(r => srv.listen(0, '127.0.0.1', () => r()))
    const port = (srv.address() as any).port
    try {
      const res = new MockRes()
      GitHubStorageService.proxyDownload(`http://127.0.0.1:${port}/asset`, res as any, 'app-1.2.3.apk')
      await new Promise(r => setTimeout(r, 300))
      assert.strictEqual(res.statusCode, 200, `status ${res.statusCode}`)
      assert.strictEqual(res.headers['content-type'], 'application/vnd.android.package-archive')
      assert(/app-1\.2\.3\.apk/.test(res.headers['content-disposition'] || ''), 'filename not preserved')
      assert(res.body.equals(FAKE_APK), 'body mismatch')
    } finally { srv.close() }
  })

  // ── 4. Full route-level chain ──────────────────────────────────────────────
  const app = require('../index').default
  const server = http.createServer(app)
  await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()))
  const base = `http://127.0.0.1:${(server.address() as any).port}`
  console.log(`\n  [server] ${base}\n`)

  const APP = { id: 'app-1', package_name: 'com.lattice.app', public_key: 'pk_live_test', name: 'Lattice' }
  const RELEASE = {
    id: 'rel-abc', app_id: 'app-1', version_name: '2.5.0', version_code: 25, channel: 'stable',
    status: 'live', rollout_percent: 100, mandatory: false, allow_downgrade: false,
    apk_path: GH_ASSET, sha256: 'deadbeef', release_notes: 'notes', package_name: 'com.lattice.app',
  }
  setApp(APP); setLatestRelease(RELEASE); setRelease(RELEASE)

  await check('OTA update API returns an ApexHub HTTPS download URL (not api.github.com)', async () => {
    const r = await request(base, '/api/update/com.lattice.app?channel=stable&installed=1', { 'x-api-key': 'pk_live_test' })
    assert.strictEqual(r.status, 200, `status ${r.status}: ${r.body.toString()}`)
    const json = JSON.parse(r.body.toString())
    assert.strictEqual(json.updateAvailable, true, 'updateAvailable should be true')
    assert(json.downloadUrl.startsWith('https://'), `not https: ${json.downloadUrl}`)
    assert(json.downloadUrl.includes('apex-hub-production.vercel.app'), `wrong host: ${json.downloadUrl}`)
    assert(json.downloadUrl.endsWith('/api/releases/rel-abc/download'), `unexpected path: ${json.downloadUrl}`)
    assert(!/github\.com/i.test(json.downloadUrl), 'downloadUrl must not reference a github host')
  })

  await check('Development APK downloads reject requests without tester access', async () => {
    const originalHasAccess = store.testers.hasAccess
    setRelease({ ...RELEASE, environment: 'development' })
    store.testers.hasAccess = async () => false
    try {
      const r = await request(base, '/api/releases/rel-abc/download')
      assert.strictEqual(r.status, 403, `status ${r.status}: ${r.body.toString()}`)
    } finally {
      store.testers.hasAccess = originalHasAccess
      setRelease(RELEASE)
    }
  })

  await check('Development APK downloads accept valid tester sessions and short-lived links', async () => {
    process.env.GITHUB_PAT = 'ghp_server_side_secret'
    const originalHasAccess = store.testers.hasAccess
    setRelease({ ...RELEASE, environment: 'development' })
    store.testers.hasAccess = async (appId: string, tokenHash: string) =>
      appId === 'app-1' && tokenHash === hashOpaqueToken('active-tester-token')
    const stub = stubHttpsGet(() => ({
      statusCode: 200,
      headers: { 'content-length': String(FAKE_APK.length) },
      body: FAKE_APK.toString('binary'),
    }))
    try {
      const testerResponse = await request(base, '/api/releases/rel-abc/download', {
        'x-tester-token': 'active-tester-token',
      })
      assert.strictEqual(testerResponse.status, 200, `tester status ${testerResponse.status}`)

      const downloadToken = createDevelopmentDownloadToken(
        'rel-abc',
        'app-1',
        hashOpaqueToken('active-tester-token'),
      )
      const signedResponse = await request(
        base,
        `/api/releases/rel-abc/download?download_token=${encodeURIComponent(downloadToken)}`,
      )
      assert.strictEqual(signedResponse.status, 200, `signed URL status ${signedResponse.status}`)
    } finally {
      stub.restore()
      store.testers.hasAccess = originalHasAccess
      setRelease(RELEASE)
    }
  })

  await check('download endpoint streams the private GitHub asset (302 -> 200)', async () => {
    process.env.GITHUB_PAT = 'ghp_server_side_secret'
    const stub = stubHttpsGet(opts => {
      if (opts.hostname === 'api.github.com') {
        return { statusCode: 302, headers: { location: 'https://objects.githubusercontent.com/signed?token=x' } }
      }
      return { statusCode: 200, headers: { 'content-length': String(FAKE_APK.length) }, body: FAKE_APK.toString('binary') }
    })
    try {
      const r = await request(base, '/api/releases/rel-abc/download')
      assert.strictEqual(r.status, 200, `status ${r.status}: ${r.body.toString()}`)
      assert.strictEqual(r.headers['content-type'], 'application/vnd.android.package-archive')
      assert(/filename="2\.5\.0\.apk"/.test(r.headers['content-disposition'] || ''), `bad disposition: ${r.headers['content-disposition']}`)
      assert(Buffer.compare(r.body, FAKE_APK) === 0, 'APK bytes not streamed through')
      // PAT attached on the api.github.com hop...
      const first = stub.seen[0]
      assert(first.headers['Authorization'] === 'token ghp_server_side_secret', 'PAT not attached on first hop')
      // ...and DROPPED at the pre-signed CDN hop (double-auth would 400).
      const second = stub.seen[1]
      assert.strictEqual(second.hostname, 'objects.githubusercontent.com')
      assert(!second.headers['Authorization'], 'Authorization must be dropped at signed CDN hop')
    } finally { stub.restore() }
  })

  await check('the GITHUB_PAT never appears in the response body', async () => {
    process.env.GITHUB_PAT = 'ghp_server_side_secret'
    const stub = stubHttpsGet(() => ({ statusCode: 302, headers: { location: 'https://objects.githubusercontent.com/s' } }))
    try {
      const r = await request(base, '/api/releases/rel-abc/download')
      assert(!r.body.toString('binary').includes('ghp_server_side_secret'), 'PAT leaked into body')
    } finally { stub.restore() }
  })

  await check('GitHub authentication failure (403) surfaces as a server error (502), not 404', async () => {
    process.env.GITHUB_PAT = 'ghp_server_side_secret'
    const stub = stubHttpsGet(() => ({ statusCode: 403, headers: {} }))
    try {
      const r = await request(base, '/api/releases/rel-abc/download')
      assert(r.status === 502, `expected 502, got ${r.status}`)
    } finally { stub.restore() }
  })

  await check('missing PAT + GitHub 404 surfaces as 503 (config error), not a client 404', async () => {
    process.env.GITHUB_PAT = ''
    delete process.env.GITHUB_TOKEN
    const stub = stubHttpsGet(() => ({ statusCode: 404, headers: {} }))
    try {
      const r = await request(base, '/api/releases/rel-abc/download')
      assert(r.status === 503, `expected 503, got ${r.status}`)
    } finally { stub.restore() }
  })

  await check('genuinely missing GitHub asset returns 404', async () => {
    process.env.GITHUB_PAT = 'ghp_server_side_secret'
    const stub = stubHttpsGet(() => ({ statusCode: 404, headers: {} }))
    try {
      const r = await request(base, '/api/releases/rel-abc/download')
      assert.strictEqual(r.status, 404, `expected 404, got ${r.status}`)
    } finally { stub.restore() }
  })

  await check('unknown release id returns 404', async () => {
    setRelease(null)
    try {
      const r = await request(base, '/api/releases/does-not-exist/download')
      assert.strictEqual(r.status, 404, `expected 404, got ${r.status}`)
    } finally { setRelease(RELEASE) }
  })

  await check('locally-stored release with a vanished local file returns 404', async () => {
    setRelease({ ...RELEASE, apk_path: '/tmp/apex-data/apks/gone.apk' })
    try {
      const r = await request(base, '/api/releases/rel-abc/download')
      assert.strictEqual(r.status, 404, `expected 404, got ${r.status}`)
    } finally { setRelease(RELEASE) }
  })

  await check('logs never contain the GITHUB_PAT', async () => {
    process.env.GITHUB_PAT = 'ghp_super_secret_value_xyz'
    const captured: string[] = []
    const origLog = console.log, origWarn = console.warn, origErr = console.error
    console.log = (...a: any[]) => { captured.push(a.join(' ')); origLog(...a) }
    console.warn = (...a: any[]) => { captured.push(a.join(' ')); origWarn(...a) }
    console.error = (...a: any[]) => { captured.push(a.join(' ')); origErr(...a) }
    const stub = stubHttpsGet(() => ({ statusCode: 403, headers: {} }))
    try {
      await request(base, '/api/releases/rel-abc/download')
    } finally {
      stub.restore(); console.log = origLog; console.warn = origWarn; console.error = origErr
    }
    const hit = captured.find(l => l.includes('ghp_super_secret_value_xyz'))
    assert(!hit, `PAT leaked into logs: ${hit}`)
    assert(captured.some(l => l.includes('githubStatus=403')), 'expected a githubStatus log line')
  })

  server.close()
  console.log(`\n${failed === 0 ? '\u2705' : '\u274C'} ${passed} passed, ${failed} failed\n`)
  if (failed > 0) process.exit(1)
}

main().catch(err => { console.error('Test harness crashed:', err); process.exit(1) })
