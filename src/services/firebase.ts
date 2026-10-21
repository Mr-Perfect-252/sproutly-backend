import { initializeApp, getApps, cert, applicationDefault, type App, type ServiceAccount } from 'firebase-admin/app'
import { getFirestore, type Firestore } from 'firebase-admin/firestore'
import { getStorage } from 'firebase-admin/storage'
import { getAuth, type Auth } from 'firebase-admin/auth'
import fs from 'fs'
import os from 'os'
import path from 'path'

let firebaseApp: App | null = null
let isInitialized = false

function initFirebase(): App | null {
  if (isInitialized) return firebaseApp
  isInitialized = true

  try {
    const existing = getApps()
    if (existing.length > 0) {
      firebaseApp = existing[0]
      return firebaseApp
    }

    // 1. JSON Service Account string or file path
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
      let serviceAccount: ServiceAccount
      if (process.env.FIREBASE_SERVICE_ACCOUNT.trim().startsWith('{')) {
        serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
      } else if (fs.existsSync(process.env.FIREBASE_SERVICE_ACCOUNT)) {
        const raw = fs.readFileSync(process.env.FIREBASE_SERVICE_ACCOUNT, 'utf8')
        serviceAccount = JSON.parse(raw)
      } else {
        throw new Error('FIREBASE_SERVICE_ACCOUNT is neither valid JSON nor a file path')
      }

      firebaseApp = initializeApp({
        credential: cert(serviceAccount),
        storageBucket: process.env.FIREBASE_STORAGE_BUCKET || `${serviceAccount.projectId}.appspot.com`,
      })
      console.log('[Firebase] Initialized with FIREBASE_SERVICE_ACCOUNT successfully')
      return firebaseApp
    }

    // 2. Individual environment variables
    const projectId = process.env.FIREBASE_PROJECT_ID
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL
    let privateKey = process.env.FIREBASE_PRIVATE_KEY

    if (projectId && clientEmail && privateKey) {
      if (privateKey.includes('\\n')) {
        privateKey = privateKey.replace(/\\n/g, '\n')
      }

      const storageBucket = process.env.FIREBASE_STORAGE_BUCKET || `${projectId}.appspot.com`

      firebaseApp = initializeApp({
        credential: cert({
          projectId,
          clientEmail,
          privateKey,
        }),
        storageBucket,
      })
      console.log(`[Firebase] Initialized with individual env vars (Project: ${projectId}, Bucket: ${storageBucket})`)
      return firebaseApp
    }

    // 3. Refresh token (FIREBASE_TOKEN or FIREBASE_REFRESH_TOKEN) via ADC
    const refreshTokenVal = process.env.FIREBASE_TOKEN || process.env.FIREBASE_REFRESH_TOKEN
    if (refreshTokenVal && !process.env.GOOGLE_APPLICATION_CREDENTIALS) {
      try {
        const tmpDir = process.env.TMPDIR || process.env.TEMP || os.tmpdir()
        const credPath = path.join(tmpDir, 'firebase-adc-credentials.json')
        fs.writeFileSync(credPath, JSON.stringify({
          client_id: process.env.FIREBASE_CLIENT_ID || '563584335869-fgrhgmd47bqnekij5i8b5pr03ho849e6.apps.googleusercontent.com',
          client_secret: process.env.FIREBASE_CLIENT_SECRET || 'j9iVZfS8kkCEFUPaAeJV0sAi',
          refresh_token: refreshTokenVal,
          type: 'authorized_user'
        }, null, 2))
        process.env.GOOGLE_APPLICATION_CREDENTIALS = credPath
        console.log(`[Firebase] Configured Application Default Credentials from token to ${credPath}`)
      } catch (err: any) {
        console.warn('[Firebase] Could not configure ADC from token:', err?.message)
      }
    }

    // 4. Google Application Default Credentials
    if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
      firebaseApp = initializeApp({
        credential: applicationDefault(),
        projectId: process.env.FIREBASE_PROJECT_ID,
        storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
      })
      console.log(`[Firebase] Initialized with GOOGLE_APPLICATION_CREDENTIALS (Project: ${process.env.FIREBASE_PROJECT_ID || 'auto'})`)
      return firebaseApp
    }

    console.log('[Firebase] No credentials configured. Running in local/SQLite storage mode.')
    return null
  } catch (err: any) {
    console.warn('[Firebase] Initialization failed:', err.message)
    firebaseApp = null
    return null
  }
}

export function isFirebaseConfigured(): boolean {
  return initFirebase() !== null
}

export function getFirestoreDb(): Firestore | null {
  const app = initFirebase()
  if (!app) return null
  try {
    return getFirestore(app)
  } catch (e) {
    console.warn('[Firebase] Could not get Firestore instance:', e)
    return null
  }
}

export function getFirebaseStorageBucket() {
  const app = initFirebase()
  if (!app) return null
  try {
    return getStorage(app).bucket()
  } catch (e) {
    console.warn('[Firebase] Could not get Storage bucket:', e)
    return null
  }
}

export function getFirebaseAuth(): Auth | null {
  const app = initFirebase()
  if (!app) return null
  try {
    return getAuth(app)
  } catch (e) {
    console.warn('[Firebase] Could not get Auth instance:', e)
    return null
  }
}

/**
 * Uploads an APK file from local disk to Firebase Cloud Storage.
 * Returns a permanent, fast CDN download URL.
 */
export async function uploadApkToFirebase(localFilePath: string, destFileName: string): Promise<string> {
  const bucket = getFirebaseStorageBucket()
  if (!bucket) {
    throw new Error('Firebase Storage bucket is not available')
  }

  const destination = `apks/${destFileName}`
  const [file] = await bucket.upload(localFilePath, {
    destination,
    metadata: {
      contentType: 'application/vnd.android.package-archive',
      metadata: {
        platform: 'ApexHub',
        uploadedAt: new Date().toISOString(),
      },
    },
  })

  // Make public or get public URL
  try {
    await file.makePublic()
    return `https://storage.googleapis.com/${bucket.name}/${destination}`
  } catch (err) {
    console.log('[Firebase Storage] Uniform bucket access detected, creating signed URL')
    const [signedUrl] = await file.getSignedUrl({
      action: 'read',
      expires: Date.now() + 1000 * 60 * 60 * 24 * 365 * 10, // 10 years
    })
    return signedUrl
  }
}
