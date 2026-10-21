import fs from 'fs'
import path from 'path'

// Auto-load .env from current directory or project root
for (const envCandidate of [path.resolve(process.cwd(), '.env'), path.resolve(__dirname, '../../.env'), path.resolve(__dirname, '../.env')]) {
  if (fs.existsSync(envCandidate)) {
    const envLines = fs.readFileSync(envCandidate, 'utf8').split('\n')
    for (const line of envLines) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith('#')) continue
      const eqIdx = trimmed.indexOf('=')
      if (eqIdx !== -1) {
        const k = trimmed.slice(0, eqIdx).trim()
        const v = trimmed.slice(eqIdx + 1).trim()
        if (!process.env[k]) process.env[k] = v
      }
    }
    break
  }
}

import express, { Request, Response, NextFunction } from 'express'
import cors from 'cors'
import helmet from 'helmet'
import authRoutes from './routes/auth'
import appRoutes from './routes/apps'
import releaseRoutes from './routes/releases'
import analyticsRoutes from './routes/analytics'
import ingestRoutes from './routes/ingest'
import githubRoutes from './routes/github'
import devStoreRoutes from './routes/devStore'
import { apiLimiter } from './middleware/rateLimiter'

const app = express()
const PORT = process.env.PORT || 3001

// Trust a single platform proxy hop (Vercel/Render) so req.protocol / req.secure
// reflect the real client scheme. Download URLs are still pinned to
// PUBLIC_BASE_URL; this only keeps logs and protocol-based logic correct.
app.set('trust proxy', 1)

// Security headers with Helmet
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}))

// CORS configuration (allow dev origins, Vercel deployments, or explicit origins in prod)
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim())
  : ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173']

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true)
    if (process.env.NODE_ENV !== 'production' || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return callback(null, true)
    }
    try {
      const hostname = new URL(origin).hostname
      if (hostname.endsWith('.vercel.app') || hostname === 'vercel.app') {
        return callback(null, true)
      }
    } catch {
      // ignore URL parse errors
    }
    callback(new Error(`CORS access denied for origin: ${origin}`))
  },
  credentials: true,
}))

// GitHub signs the exact request bytes; parse webhooks before the JSON middleware.
app.use(['/api/github/webhook', '/github/webhook'], express.raw({ type: 'application/json', limit: '25mb' }))

// Global JSON body parser with size limit
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true, limit: '10mb' }))

import { UPLOADS_DIR } from './store/paths'

// Rate limiting on public API surface
app.use('/api/', apiLimiter)

// Static downloads directory
app.use('/uploads', express.static(UPLOADS_DIR))

// Modular API Routes (supports both direct access and Vercel rewrites)
app.use(['/api/auth', '/auth'], authRoutes)
app.use(['/api/apps', '/apps'], appRoutes)
app.use(['/api/releases', '/releases'], releaseRoutes)
app.use(['/api/update', '/update'], releaseRoutes)
app.use(['/api/analytics', '/analytics'], analyticsRoutes)
// apex-analytics SDK ingestion (apex-analytics wire format)
app.use(['/api/v1', '/v1'], ingestRoutes)
app.use(['/api/github', '/github'], githubRoutes)
app.use('/api/dev-store', devStoreRoutes)

// Health check endpoint
app.get(['/api/health', '/health'], (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    version: '1.1.0',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
  })
})

// 404 Handler for undefined routes
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Endpoint not found' })
})

// Centralized error handling middleware
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  const status = err.status || 500
  const message = err.message || 'Internal Server Error'
  if (process.env.NODE_ENV !== 'test') {
    console.error(`[API Error] ${status}: ${message}`)
  }
  res.status(status).json({ error: message })
})

if (!process.env.VERCEL) {
  const server = app.listen(PORT, () => {
    console.log(`[Apex Hub] API server listening on http://localhost:${PORT}`)
  })

  // Graceful termination handling
  process.on('SIGTERM', () => {
    console.log('[Apex Hub] SIGTERM signal received: closing HTTP server')
    server.close(() => console.log('[Apex Hub] HTTP server closed'))
  })

  process.on('SIGINT', () => {
    console.log('[Apex Hub] SIGINT signal received: closing HTTP server')
    server.close(() => console.log('[Apex Hub] HTTP server closed'))
  })
}

export default app
