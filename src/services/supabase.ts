import { createClient, SupabaseClient } from '@supabase/supabase-js'

let supabaseInstance: SupabaseClient | null = null

export function getSupabase(): SupabaseClient | null {
  if (supabaseInstance) return supabaseInstance

  const url = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || process.env.VITE_SUPABASE_PUBLISHABLE_KEY

  if (!url || !key) {
    return null
  }

  supabaseInstance = createClient(url, key, {
    auth: { persistSession: false }
  })
  return supabaseInstance
}
