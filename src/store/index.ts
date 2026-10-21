import { requireSupabase, nowEpoch, throwOnError } from './client'
import { safeDisplayName } from '../utils/displayName'

// ─────────────────────────────────────────────────────────────────────────────
// Types (loose — mirrors the Postgres columns)
// ─────────────────────────────────────────────────────────────────────────────
export interface UserRow {
  id: string
  email: string
  name: string
  password: string
  plan: string
  created_at: number
}

export interface AppRow {
  id: string
  owner_id: string
  package_name: string
  name: string
  description: string
  icon_url: string
  screenshots: string[]
  category: string
  website_url: string
  public_key: string
  secret_key: string
  cert_fingerprint: string
  developer_name: string
  developer_id: string
  created_at: number
}

export interface ReleaseRow {
  id: string
  app_id: string
  version_name: string
  version_code: number
  channel: string
  status: string
  rollout_percent: number
  mandatory: boolean
  allow_downgrade: boolean
  update_strategy: string
  release_notes: string
  apk_path: string
  apk_size: number
  sha256: string
  cert_fingerprint: string
  min_sdk: number
  target_sdk: number
  downloads: number
  created_at: number
  environment: 'development' | 'production'
  promoted_from_id: string | null
}

/**
 * PostgREST `.or()` values are comma/parenthesis-delimited, so any of those
 * characters in user input would corrupt the filter. Strip them for safe use
 * inside `ilike` patterns.
 */
function sanitizeForOr(value: string): string {
  return value.replace(/[(),]/g, ' ').trim()
}

// ─────────────────────────────────────────────────────────────────────────────
// Users
// ─────────────────────────────────────────────────────────────────────────────
export const users = {
  async findByEmail(email: string): Promise<UserRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase.from('users').select('*').eq('email', email).maybeSingle()
    throwOnError(error, 'users.findByEmail')
    return (data as UserRow) || null
  },

  async findById(id: string): Promise<UserRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase.from('users').select('*').eq('id', id).maybeSingle()
    throwOnError(error, 'users.findById')
    return (data as UserRow) || null
  },

  async create(user: { id: string; email: string; name: string; password: string; plan?: string }): Promise<void> {
    const supabase = requireSupabase()
    const { error } = await supabase.from('users').insert({
      id: user.id,
      email: user.email,
      name: user.name,
      password: user.password,
      plan: user.plan || 'free',
      created_at: nowEpoch(),
    })
    throwOnError(error, 'users.create')
  },

  /**
   * Insert a user only if neither the id nor the email already exists — the
   * Postgres equivalent of the old `INSERT OR IGNORE`. Never throws on a
   * duplicate; used to satisfy the apps → users foreign key for Clerk/JWT users.
   */
  async ensureExists(user: { id: string; email: string; name: string; password: string }): Promise<void> {
    const supabase = requireSupabase()
    const existing = await supabase
      .from('users')
      .select('id')
      .or(`id.eq.${user.id},email.eq.${sanitizeForOr(user.email)}`)
      .maybeSingle()
    if (existing.data) return
    const { error } = await supabase.from('users').insert({
      id: user.id,
      email: user.email,
      name: user.name,
      password: user.password,
      plan: 'free',
      created_at: nowEpoch(),
    })
    // Swallow unique-violation races (23505) — another request may have inserted.
    if (error && error.code !== '23505') {
      console.warn('[store.users.ensureExists] insert warning:', error.message)
    }
  },
}

// ─────────────────────────────────────────────────────────────────────────────
// Apps
// ─────────────────────────────────────────────────────────────────────────────
export const apps = {
  async findById(id: string): Promise<AppRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase.from('apps').select('*').eq('id', id).maybeSingle()
    throwOnError(error, 'apps.findById')
    return (data as AppRow) || null
  },

  async findByPackage(pkg: string): Promise<AppRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase.from('apps').select('*').eq('package_name', pkg).maybeSingle()
    throwOnError(error, 'apps.findByPackage')
    return (data as AppRow) || null
  },

  async findByIdAndOwner(id: string, ownerId: string): Promise<AppRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('apps').select('*').eq('id', id).eq('owner_id', ownerId).maybeSingle()
    throwOnError(error, 'apps.findByIdAndOwner')
    return (data as AppRow) || null
  },

  async findByPackageAndOwner(pkg: string, ownerId: string): Promise<AppRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('apps').select('*').eq('package_name', pkg).eq('owner_id', ownerId).maybeSingle()
    throwOnError(error, 'apps.findByPackageAndOwner')
    return (data as AppRow) || null
  },

  async findByPublicKey(publicKey: string): Promise<AppRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase.from('apps').select('*').eq('public_key', publicKey).maybeSingle()
    throwOnError(error, 'apps.findByPublicKey')
    return (data as AppRow) || null
  },

  async findByPackageAndPublicKey(pkg: string, publicKey: string): Promise<AppRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('apps').select('*').eq('package_name', pkg).eq('public_key', publicKey).maybeSingle()
    throwOnError(error, 'apps.findByPackageAndPublicKey')
    return (data as AppRow) || null
  },

  async findByPublicKeyLike(fragment: string): Promise<AppRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('apps').select('*').ilike('public_key', `%${fragment}%`).limit(1)
    throwOnError(error, 'apps.findByPublicKeyLike')
    return (data && data[0] as AppRow) || null
  },

  /** True if any app (other than `exceptId`) already uses this package name. */
  async packageTakenByOther(pkg: string, exceptId: string): Promise<boolean> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('apps').select('id').eq('package_name', pkg).neq('id', exceptId).limit(1)
    throwOnError(error, 'apps.packageTakenByOther')
    return !!(data && data.length)
  },

  /**
   * Public marketplace listing. Aggregates (release count, downloads, rating)
   * are computed in JS from embedded child rows, and only `live` releases count
   * toward the public-facing totals — matching the previous SQL semantics.
   */
  async listPublic(opts: { q?: string; category?: string; sort?: string }): Promise<any[]> {
    const supabase = requireSupabase()
    let query = supabase
      .from('apps')
      .select(`
        id, package_name, name, description, icon_url, screenshots, category, created_at, developer_name,
        releases ( downloads, status, version_name, version_code, environment ),
        reviews ( rating )
      `)

    const q = (opts.q || '').trim()
    if (q && q !== 'undefined') {
      const safe = sanitizeForOr(q)
      if (safe) {
        query = query.or(`name.ilike.%${safe}%,package_name.ilike.%${safe}%,description.ilike.%${safe}%`)
      }
    }
    const category = opts.category
    if (category && category !== 'All' && category !== 'undefined') {
      query = query.eq('category', category)
    }

    const { data, error } = await query
    throwOnError(error, 'apps.listPublic')

    const summaries = (data || []).map((a: any) => {
      const liveReleases = (a.releases || []).filter((r: any) =>
        r.status === 'live' && r.environment === 'production')
      const reviews = a.reviews || []
      const totalDownloads = liveReleases.reduce((s: number, r: any) => s + (Number(r.downloads) || 0), 0)
      const reviewCount = reviews.length
      const avgRating = reviewCount
        ? reviews.reduce((s: number, r: any) => s + (Number(r.rating) || 0), 0) / reviewCount
        : 0
      const latest = liveReleases.slice().sort((x: any, y: any) => y.version_code - x.version_code)[0]
      return {
        id: a.id,
        package_name: a.package_name,
        name: a.name,
        description: a.description,
        icon_url: a.icon_url,
        category: a.category,
        created_at: a.created_at,
        developer_name: safeDisplayName(a.developer_name),
        release_count: liveReleases.length,
        total_downloads: totalDownloads,
        avg_rating: avgRating,
        review_count: reviewCount,
        latest_version: latest ? latest.version_name : null,
        latest_version_code: latest ? latest.version_code : null,
      }
    })

    const sort = opts.sort || 'downloads'
    summaries.sort((a, b) => {
      if (sort === 'rating') return b.avg_rating - a.avg_rating
      if (sort === 'newest') return b.created_at - a.created_at
      return b.total_downloads - a.total_downloads
    })
    return summaries
  },

  /**
   * Public single-app detail with flexible matching (exact package, id, fuzzy
   * package/name, or reverse-contains) preserving the previous route behavior.
   * Returns the raw matched AppRow, or null.
   */
  async findForDetail(target: string): Promise<AppRow | null> {
    const supabase = requireSupabase()

    // 1. Exact package name
    const exact = await this.findByPackage(target)
    if (exact) return exact

    // 2. Exact id
    const byId = await this.findById(target)
    if (byId) return byId

    // 3. Fuzzy: package_name contains target, or name matches target
    const safe = sanitizeForOr(target)
    if (safe) {
      const { data, error } = await supabase
        .from('apps')
        .select('*')
        .or(`package_name.ilike.%${safe}%,name.ilike.%${safe}%`)
        .limit(1)
      throwOnError(error, 'apps.findForDetail.fuzzy')
      if (data && data.length) return data[0] as AppRow
    }

    // 4. Reverse-contains: target contains an app's package_name (e.g.
    //    "com.codium.ide.mobile" matching registered "com.codium"). Small table,
    //    so scan candidates in JS. Also preserves the codium alias fallback.
    const { data: all, error: allErr } = await supabase.from('apps').select('*')
    throwOnError(allErr, 'apps.findForDetail.scan')
    const lowerTarget = target.toLowerCase()
    for (const a of (all || []) as AppRow[]) {
      if (a.package_name && lowerTarget.includes(a.package_name.toLowerCase())) return a
      if (a.id === 'app_codium_ide' && lowerTarget.includes('codium')) return a
    }
    return null
  },

  /** Developer dashboard listing: all releases count toward totals here. */
  async listByOwner(ownerId: string): Promise<any[]> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('apps')
      .select(`
        id, package_name, name, description, icon_url, screenshots, category,
        public_key, secret_key, cert_fingerprint, created_at, owner_id,
        releases ( id, version_name, version_code, channel, status, rollout_percent,
                   mandatory, release_notes, apk_size, sha256, downloads, created_at,
                   environment, promoted_from_id ),
        reviews ( rating )
      `)
      .eq('owner_id', ownerId)
    throwOnError(error, 'apps.listByOwner')

    const result = (data || []).map((a: any) => {
      const releases = (a.releases || []).slice().sort((x: any, y: any) => y.version_code - x.version_code)
      const reviews = a.reviews || []
      const reviewCount = reviews.length
      const avgRating = reviewCount
        ? reviews.reduce((s: number, r: any) => s + (Number(r.rating) || 0), 0) / reviewCount
        : 0
      const totalDownloads = releases.reduce((s: number, r: any) => s + (Number(r.downloads) || 0), 0)
      return {
        id: a.id,
        package_name: a.package_name,
        name: a.name,
        description: a.description,
        icon_url: a.icon_url,
        screenshots: a.screenshots || [],
        category: a.category,
        public_key: a.public_key,
        secret_key: a.secret_key,
        cert_fingerprint: a.cert_fingerprint,
        created_at: a.created_at,
        owner_id: a.owner_id,
        total_downloads: totalDownloads,
        avg_rating: avgRating,
        review_count: reviewCount,
        releases,
      }
    })
    result.sort((a, b) => b.created_at - a.created_at)
    return result
  },

  async create(app: {
    id: string; owner_id: string; package_name: string; name: string
    description?: string; category?: string; website_url?: string; icon_url?: string
    screenshots?: string[]
    public_key: string; secret_key: string
    developer_name?: string; developer_id?: string
  }): Promise<void> {
    const supabase = requireSupabase()
    const { error } = await supabase.from('apps').insert({
      id: app.id,
      owner_id: app.owner_id,
      package_name: app.package_name,
      name: app.name,
      description: app.description || '',
      icon_url: app.icon_url || '',
      screenshots: app.screenshots || [],
      category: app.category || 'Utilities',
      website_url: app.website_url || '',
      public_key: app.public_key,
      secret_key: app.secret_key,
      developer_name: app.developer_name || '',
      developer_id: app.developer_id || app.owner_id,
      created_at: nowEpoch(),
    })
    throwOnError(error, 'apps.create')
  },

  async update(id: string, fields: Record<string, any>): Promise<void> {
    const supabase = requireSupabase()
    const patch: Record<string, any> = {}
    for (const [k, v] of Object.entries(fields)) {
      if (v !== undefined && v !== null) patch[k] = v
    }
    if (Object.keys(patch).length === 0) return
    const { error } = await supabase.from('apps').update(patch).eq('id', id)
    throwOnError(error, 'apps.update')
  },

  async remove(id: string): Promise<void> {
    const supabase = requireSupabase()
    const { error } = await supabase.from('apps').delete().eq('id', id)
    throwOnError(error, 'apps.remove')
  },
}

// ─────────────────────────────────────────────────────────────────────────────
// Releases
// ─────────────────────────────────────────────────────────────────────────────
export const releases = {
  async listByAppAndEnvironment(
    appId: string,
    environment: 'development' | 'production',
  ): Promise<ReleaseRow[]> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('releases')
      .select(`id, app_id, version_name, version_code, channel, status, rollout_percent,
               mandatory, allow_downgrade, update_strategy, release_notes, apk_size, sha256,
               cert_fingerprint, min_sdk, target_sdk, downloads, created_at, environment,
               promoted_from_id`)
      .eq('app_id', appId)
      .eq('environment', environment)
      .eq('status', 'live')
      .order('version_code', { ascending: false })
    throwOnError(error, 'releases.listByAppAndEnvironment')
    return (data || []) as ReleaseRow[]
  },

  async latestLiveByChannel(
    appId: string,
    channel: string,
    environment: 'development' | 'production' = 'production',
  ): Promise<ReleaseRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('releases').select('*')
      .eq('app_id', appId).eq('channel', channel).eq('status', 'live').eq('environment', environment)
      .order('version_code', { ascending: false }).limit(1)
    throwOnError(error, 'releases.latestLiveByChannel')
    return (data && data[0] as ReleaseRow) || null
  },

  async latestByApp(appId: string): Promise<ReleaseRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('releases').select('version_code')
      .eq('app_id', appId).order('version_code', { ascending: false }).limit(1)
    throwOnError(error, 'releases.latestByApp')
    return (data && data[0] as ReleaseRow) || null
  },

  /** Releases shown on the public app-detail page (live + archived). */
  async listVisibleByApp(appId: string): Promise<ReleaseRow[]> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('releases')
      .select(`id, version_name, version_code, channel, status, rollout_percent,
               mandatory, update_strategy, release_notes, apk_size, sha256,
               cert_fingerprint, min_sdk, target_sdk, downloads, created_at,
               environment, promoted_from_id`)
      .eq('app_id', appId).in('status', ['live', 'archived'])
      .eq('environment', 'production')
      .order('version_code', { ascending: false })
    throwOnError(error, 'releases.listVisibleByApp')
    return (data || []) as ReleaseRow[]
  },

  async findByIdWithApp(id: string): Promise<any | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('releases').select('*, apps ( public_key, package_name )').eq('id', id).maybeSingle()
    throwOnError(error, 'releases.findByIdWithApp')
    if (!data) return null
    const { apps: appRel, ...rest } = data as any
    return { ...rest, public_key: appRel?.public_key || '', package_name: appRel?.package_name || '' }
  },

  async findByIdAndOwner(id: string, ownerId: string): Promise<ReleaseRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('releases').select('*, apps!inner ( owner_id )')
      .eq('id', id).eq('apps.owner_id', ownerId).maybeSingle()
    throwOnError(error, 'releases.findByIdAndOwner')
    if (!data) return null
    const { apps: _drop, ...rest } = data as any
    return rest as ReleaseRow
  },

  async create(rel: {
    id: string; app_id: string; version_name: string; version_code: number
    channel?: string; status?: string; rollout_percent?: number
    mandatory?: boolean; allow_downgrade?: boolean; update_strategy?: string
    release_notes?: string; apk_path: string; apk_size?: number; sha256?: string
    cert_fingerprint?: string; min_sdk?: number; target_sdk?: number
    environment?: 'development' | 'production'; promoted_from_id?: string | null
  }): Promise<void> {
    const supabase = requireSupabase()
    const { error } = await supabase.from('releases').insert({
      id: rel.id,
      app_id: rel.app_id,
      version_name: rel.version_name,
      version_code: rel.version_code,
      channel: rel.channel || 'stable',
      status: rel.status || 'live',
      rollout_percent: rel.rollout_percent ?? 100,
      mandatory: !!rel.mandatory,
      allow_downgrade: !!rel.allow_downgrade,
      update_strategy: rel.update_strategy || 'FLEXIBLE',
      release_notes: rel.release_notes || '',
      apk_path: rel.apk_path,
      apk_size: rel.apk_size ?? 0,
      sha256: rel.sha256 || '',
      cert_fingerprint: rel.cert_fingerprint || '',
      min_sdk: rel.min_sdk ?? 21,
      target_sdk: rel.target_sdk ?? 34,
      environment: rel.environment || 'production',
      promoted_from_id: rel.promoted_from_id || null,
      downloads: 0,
      created_at: nowEpoch(),
    })
    throwOnError(error, 'releases.create')
  },

  async update(id: string, fields: Record<string, any>): Promise<void> {
    const supabase = requireSupabase()
    const patch: Record<string, any> = {}
    for (const [k, v] of Object.entries(fields)) {
      if (v !== undefined && v !== null) patch[k] = v
    }
    if (Object.keys(patch).length === 0) return
    const { error } = await supabase.from('releases').update(patch).eq('id', id)
    throwOnError(error, 'releases.update')
  },

  async incrementDownloads(id: string): Promise<void> {
    const supabase = requireSupabase()
    const { data: row } = await supabase.from('releases').select('downloads').eq('id', id).maybeSingle()
    const next = (Number(row?.downloads) || 0) + 1
    const { error } = await supabase.from('releases').update({ downloads: next }).eq('id', id)
    throwOnError(error, 'releases.incrementDownloads')
  },

  /** Hard-delete a release row. Returns true if a row was removed. */
  async remove(id: string): Promise<boolean> {
    const supabase = requireSupabase()
    const { data, error } = await supabase.from('releases').delete().eq('id', id).select('id')
    throwOnError(error, 'releases.remove')
    return Array.isArray(data) && data.length > 0
  },

  async promoteDevelopmentRelease(id: string, ownerId: string, promotedId: string): Promise<ReleaseRow | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('releases')
      .select('*, apps!inner(owner_id)')
      .eq('id', id)
      .eq('apps.owner_id', ownerId)
      .eq('environment', 'development')
      .eq('status', 'live')
      .maybeSingle()
    throwOnError(error, 'releases.promoteDevelopmentRelease.lookup')
    if (!data) return null

    const { apps: _app, ...source } = data as any
    const { error: insertError } = await supabase.from('releases').insert({
      ...source,
      id: promotedId,
      environment: 'production',
      promoted_from_id: id,
      status: 'live',
      downloads: 0,
      created_at: nowEpoch(),
    })
    throwOnError(insertError, 'releases.promoteDevelopmentRelease.insert')
    return { ...source, id: promotedId, environment: 'production', promoted_from_id: id, downloads: 0 } as ReleaseRow
  },
}

export interface TesterRow {
  id: string
  app_id: string
  email: string
  name: string
  status: 'invited' | 'active'
  created_at: number
  invite_expires_at: number | null
  accepted_at: number | null
}

export const testers = {
  async listByAppAndOwner(appId: string, ownerId: string): Promise<TesterRow[]> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('app_testers')
      .select('id, app_id, email, name, status, created_at, invite_expires_at, accepted_at, apps!inner(owner_id)')
      .eq('app_id', appId)
      .eq('apps.owner_id', ownerId)
      .order('created_at', { ascending: false })
    throwOnError(error, 'testers.listByAppAndOwner')
    return (data || []).map(({ apps: _app, ...row }: any) => row as TesterRow)
  },

  async add(input: {
    id: string
    appId: string
    email: string
    name: string
    inviteTokenHash: string
    inviteExpiresAt: number
  }): Promise<TesterRow> {
    const supabase = requireSupabase()
    const row = {
      id: input.id,
      app_id: input.appId,
      email: input.email,
      name: input.name,
      status: 'invited',
      created_at: nowEpoch(),
      invite_token_hash: input.inviteTokenHash,
      invite_expires_at: input.inviteExpiresAt,
      accepted_at: null,
    }
    const { error } = await supabase.from('app_testers').insert(row)
    throwOnError(error, 'testers.add')
    return row as TesterRow
  },

  async findInviteByHash(tokenHash: string): Promise<{ tester: TesterRow; app: Pick<AppRow, 'id' | 'name' | 'package_name' | 'icon_url'> } | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('app_testers')
      .select('id, app_id, email, name, status, created_at, invite_expires_at, accepted_at, apps!inner(id, name, package_name, icon_url)')
      .eq('invite_token_hash', tokenHash)
      .in('status', ['invited', 'active'])
      .maybeSingle()
    throwOnError(error, 'testers.findInviteByHash')
    if (!data) return null
    const { apps: app, ...tester } = data as any
    return { tester: tester as TesterRow, app: app as Pick<AppRow, 'id' | 'name' | 'package_name' | 'icon_url'> }
  },

  async acceptInvite(input: {
    tokenHash: string
    accessTokenHash: string
    accessExpiresAt: number
  }): Promise<{ tester: TesterRow; app: Pick<AppRow, 'id' | 'name' | 'package_name' | 'icon_url'> } | null> {
    const supabase = requireSupabase()
    const now = nowEpoch()
    const { data, error } = await supabase
      .from('app_testers')
      .update({
        status: 'active',
        access_token_hash: input.accessTokenHash,
        access_expires_at: input.accessExpiresAt,
        accepted_at: now,
      })
      .eq('invite_token_hash', input.tokenHash)
      .eq('status', 'invited')
      .gt('invite_expires_at', now)
      .select('id, app_id, email, name, status, created_at, invite_expires_at, accepted_at, apps!inner(id, name, package_name, icon_url)')
      .maybeSingle()
    throwOnError(error, 'testers.acceptInvite')
    if (!data) return null
    const { apps: app, ...tester } = data as any
    return { tester: tester as TesterRow, app: app as Pick<AppRow, 'id' | 'name' | 'package_name' | 'icon_url'> }
  },

  async hasAccess(appId: string, accessTokenHash: string): Promise<boolean> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('app_testers')
      .select('id')
      .eq('app_id', appId)
      .eq('access_token_hash', accessTokenHash)
      .eq('status', 'active')
      .gt('access_expires_at', nowEpoch())
      .limit(1)
    throwOnError(error, 'testers.hasAccess')
    return Boolean(data?.length)
  },

  async remove(id: string, appId: string): Promise<boolean> {
    const supabase = requireSupabase()
    const { data, error } = await supabase.from('app_testers')
      .delete()
      .eq('id', id)
      .eq('app_id', appId)
      .select('id')
    throwOnError(error, 'testers.remove')
    return Array.isArray(data) && data.length > 0
  },
}

// ─────────────────────────────────────────────────────────────────────────────
// Reviews
// ─────────────────────────────────────────────────────────────────────────────
export const reviews = {
  async listByApp(appId: string, limit = 50): Promise<any[]> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('reviews')
      .select('id, user_name, rating, body, created_at, developer_reply, developer_replied_at')
      .eq('app_id', appId)
      .order('created_at', { ascending: false })
      .limit(limit)
    throwOnError(error, 'reviews.listByApp')
    return data || []
  },

  async listByApps(appIds: string[], limit = 200): Promise<any[]> {
    if (appIds.length === 0) return []
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('reviews')
      .select('id, app_id, user_name, rating, body, created_at, developer_reply, developer_replied_at')
      .in('app_id', appIds)
      .order('created_at', { ascending: false })
      .limit(limit)
    throwOnError(error, 'reviews.listByApps')
    return data || []
  },

  async create(review: {
    id: string; app_id: string; user_name: string; rating: number; body?: string
  }): Promise<any> {
    const supabase = requireSupabase()
    const row = {
      id: review.id,
      app_id: review.app_id,
      user_name: review.user_name,
      rating: review.rating,
      body: review.body || '',
      developer_reply: '',
      developer_replied_at: null,
      created_at: nowEpoch(),
    }
    const { error } = await supabase.from('reviews').insert(row)
    throwOnError(error, 'reviews.create')
    return row
  },

  async reply(id: string, appId: string, reply: string): Promise<any | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('reviews')
      .update({ developer_reply: reply, developer_replied_at: nowEpoch() })
      .eq('id', id)
      .eq('app_id', appId)
      .select('id, app_id, developer_reply, developer_replied_at')
      .maybeSingle()
    throwOnError(error, 'reviews.reply')
    return data || null
  },
}

export interface AnalyticsEventRow {
  id: string
  app_id: string
  event_type: string
  event_name: string
  device_id: string
  os_version: string
  device_model: string
  session_sec: number
  metadata: Record<string, any>
  created_at: number
}

export const analytics = {
  async create(event: {
    id: string; app_id: string; event_type: string; event_name?: string
    device_id?: string; os_version?: string; device_model?: string
    session_sec?: number; metadata?: Record<string, any>
  }): Promise<AnalyticsEventRow> {
    const supabase = requireSupabase()
    const row: AnalyticsEventRow = {
      id: event.id,
      app_id: event.app_id,
      event_type: event.event_type,
      event_name: event.event_name || event.event_type,
      device_id: event.device_id || '',
      os_version: event.os_version || '',
      device_model: event.device_model || '',
      session_sec: event.session_sec || 0,
      metadata: event.metadata || {},
      created_at: nowEpoch(),
    }
    const { error } = await supabase.from('analytics_events').insert(row)
    throwOnError(error, 'analytics.create')
    return row
  },

  async listByApp(appId: string, limit = 500): Promise<AnalyticsEventRow[]> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('analytics_events')
      .select('id, app_id, event_type, event_name, device_id, os_version, device_model, session_sec, metadata, created_at')
      .eq('app_id', appId)
      .order('created_at', { ascending: false })
      .limit(limit)
    throwOnError(error, 'analytics.listByApp')
    return data || []
  },
}
