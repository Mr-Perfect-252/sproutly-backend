import { getSupabase } from '../services/supabase'
import type { SupabaseClient } from '@supabase/supabase-js'

/**
 * Returns the configured Supabase client, or throws a 503 error if Supabase is
 * not configured. Supabase is now the single source of truth for all
 * structured data (users, apps, releases, reviews, analytics), so a missing
 * configuration is a hard failure rather than a fallback to a local store.
 */
export function requireSupabase(): SupabaseClient {
  const supabase = getSupabase()
  if (!supabase) {
    const err: any = new Error(
      'Database is not configured. Set SUPABASE_URL and a Supabase key (SUPABASE_SERVICE_ROLE_KEY or SUPABASE_KEY).'
    )
    err.status = 503
    throw err
  }
  return supabase
}

/** Current Unix epoch in seconds — matches the BIGINT `created_at` columns. */
export function nowEpoch(): number {
  return Math.floor(Date.now() / 1000)
}

/**
 * Normalizes a PostgREST error into a thrown Error carrying an HTTP status so
 * the central error handler can surface it. `PGRST116` (no rows for
 * `.single()`) is treated as "not found" by callers and handled there.
 */
export function throwOnError(error: any, context: string): void {
  if (!error) return
  const err: any = new Error(`${context}: ${error.message || 'database error'}`)
  err.status = error.status || 500
  err.code = error.code
  throw err
}
