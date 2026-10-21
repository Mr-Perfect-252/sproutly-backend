import path from 'path'
import fs from 'fs'
import { UPLOADS_DIR } from '../../store/paths'
import { GitHubStorageService } from '../githubStorage'

/**
 * Storage abstraction for APK binaries.
 *
 * GitHub is the single source of truth for published APKs (see
 * GitHubStorageService, which stores them as Release assets). This service only
 * manages the *ephemeral* local temp copy used during upload/validation and
 * provides URL-aware helpers so the release download endpoint can handle both
 * remote (GitHub) and local `apk_path` values.
 */
export interface IStorageService {
  save(filename: string, localTempPath: string): Promise<string>
  getDownloadUrl(reqProtocol: string, reqHost: string, releaseId: string, filename: string): string
  exists(targetPath: string): boolean
  delete(targetPath: string): Promise<void>
}

const isRemote = (p: string): boolean =>
  p.startsWith('http://') || p.startsWith('https://')

export class LocalStorageService implements IStorageService {
  private uploadsDir: string

  constructor(uploadsDir: string) {
    this.uploadsDir = uploadsDir
    try {
      fs.mkdirSync(this.uploadsDir, { recursive: true })
    } catch {}
  }

  async save(filename: string, localTempPath: string): Promise<string> {
    const destination = path.join(this.uploadsDir, filename)
    if (localTempPath !== destination) {
      fs.copyFileSync(localTempPath, destination)
      try {
        fs.unlinkSync(localTempPath)
      } catch {}
    }
    return destination
  }

  getDownloadUrl(_reqProtocol: string, _reqHost: string, releaseId: string, _filename: string): string {
    // Always route downloads through our own endpoint on the fixed, HTTPS
    // production domain. For GitHub-backed releases this endpoint
    // proxy-streams the binary with the server-side PAT, so private storage
    // repos work and no token is ever exposed to clients. We deliberately do
    // NOT trust req.protocol/req.host here: behind a proxy they can be http://,
    // and Android blocks cleartext OTA downloads.
    return GitHubStorageService.publicDownloadUrl(releaseId)
  }

  exists(targetPath: string): boolean {
    // Remote (GitHub/Drive) URLs are considered to exist; validity is verified
    // when the download endpoint proxies them.
    if (isRemote(targetPath)) return true
    return fs.existsSync(targetPath)
  }

  async delete(targetPath: string): Promise<void> {
    // Remote binaries live in the GitHub storage repo and are not deleted here.
    if (isRemote(targetPath)) return
    if (fs.existsSync(targetPath)) {
      fs.unlinkSync(targetPath)
    }
  }
}

export const storageService: IStorageService = new LocalStorageService(UPLOADS_DIR)
