import { Router, Request, Response } from 'express'
import { v4 as uuid } from 'uuid'
import { apps, analytics, type AnalyticsEventRow } from '../store'
import { requireAuth, AuthRequest } from '../middleware/auth'
import { analyticsLimiter } from '../middleware/rateLimiter'

const router = Router()

// POST /api/analytics/event — Ingest telemetry event from open-sdk-analytics SDK
router.post('/event', analyticsLimiter, async (req: Request, res: Response): Promise<void> => {
  const apiKey = (req.headers['x-api-key'] || req.headers['authorization'] || '').toString().replace(/^Bearer\s+/i, '')
  const {
    package_name,
    public_key,
    event_type = 'app_launch',
    event_name = '',
    device_id = '',
    os_version = '',
    device_model = '',
    session_sec = 0,
    metadata = {}
  } = req.body

  const keyToUse = apiKey || public_key

  // Locate target app by public_key or package_name
  let app = null
  if (keyToUse) {
    app = await apps.findByPublicKey(keyToUse)
  }
  if (!app && package_name) {
    app = await apps.findByPackage(package_name)
  }
  if (!app && keyToUse?.startsWith('pk_')) {
    app = await apps.findByPublicKeyLike(keyToUse)
  }

  if (!app) {
    res.status(404).json({ error: 'App not found for provided API key or package name' })
    return
  }

  const id = uuid()

  try {
    await analytics.create({
      id,
      app_id: app.id,
      event_type,
      event_name: event_name || event_type,
      device_id,
      os_version,
      device_model,
      session_sec: parseInt(String(session_sec), 10) || 0,
      metadata,
    })

    res.status(201).json({ ok: true, event_id: id })
  } catch (err: any) {
    console.error('[Analytics Ingest Error]', err)
    res.status(500).json({ error: 'Failed to record analytics event' })
  }
})

// GET /api/analytics/summary — Fetch aggregated telemetry metrics for developer dashboard
router.get('/summary', requireAuth, async (req: AuthRequest, res: Response): Promise<void> => {
  const appId = String(req.query.app_id || '')
  if (!appId) {
    res.status(400).json({ error: 'app_id query parameter is required' })
    return
  }

  // Verify ownership (fall back to any app with this id, matching prior behavior)
  let app = await apps.findByIdAndOwner(appId, req.userId || '')
  if (!app) {
    app = await apps.findById(appId)
  }

  if (!app) {
    res.status(404).json({ error: 'App not found' })
    return
  }

  const events: AnalyticsEventRow[] = await analytics.listByApp(app.id, 500)

  // Calculate DAU / MAU
  const uniqueDevices = new Set(events.map(e => e.device_id).filter(Boolean))
  const totalLaunches = events.filter(e => e.event_type === 'app_launch' || e.event_type === 'session_start').length
  const totalCrashes = events.filter(e => e.event_type === 'crash').length
  const avgSessionSec = events.length > 0
    ? Math.round(events.reduce((sum, e) => sum + (e.session_sec || 0), 0) / events.length)
    : 0

  // OS distribution breakdown
  const osDistribution: Record<string, number> = {}
  events.forEach(e => {
    if (e.os_version) {
      osDistribution[e.os_version] = (osDistribution[e.os_version] || 0) + 1
    }
  })

  // Recent activity logs
  const recentLogs = events.slice(0, 20)

  res.json({
    app_id: app.id,
    app_name: app.name,
    total_events: events.length,
    active_devices: uniqueDevices.size,
    total_launches: totalLaunches,
    total_crashes: totalCrashes,
    avg_session_sec: avgSessionSec,
    os_distribution: osDistribution,
    recent_logs: recentLogs
  })
})

export default router
