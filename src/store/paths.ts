import path from 'path'
import fs from 'fs'
import os from 'os'

/**
 * Filesystem locations used only for *transient* APK handling (multer temp
 * files and, when Supabase Storage is unavailable, local fallback binaries).
 *
 * Note: application data (users, apps, releases, reviews, analytics) is NO
 * LONGER stored on disk. Postgres/Supabase is the single source of truth and is
 * read from / written to directly. These directories only ever hold binary
 * upload artifacts, never structured records.
 */
export const DATA_DIR = process.env.VERCEL
  ? path.join(os.tmpdir(), 'apex-data')
  : path.join(__dirname, '../../data')

export const UPLOADS_DIR = path.join(DATA_DIR, 'apks')

try {
  fs.mkdirSync(DATA_DIR, { recursive: true })
  fs.mkdirSync(UPLOADS_DIR, { recursive: true })
} catch (e) {
  console.warn('[Storage] Failed to create upload directories:', e)
}
