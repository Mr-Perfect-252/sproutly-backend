import { Router, Request, Response } from 'express'
import { v4 as uuid } from 'uuid'
import { apps, analytics } from '../store'
import { analyticsLimiter } from '../middleware/rateLimiter'

/**
 * apex-analytics SDK ingestion.
 *
 * The published SDK `io.github.mr-perfect-252:apex-analytics` posts the
 * apex-analytics wire format (descended from open-sdk-analytics) to:
 *   POST /api/v1/track          -> { events: [ AnalyticsEvent, ... ] }
 *   POST /api/v1/crash-report   -> { reports: [ CrashReport, ... ] }  (or a single object)
 *
 * Auth: `Authorization: Bearer pk_live_...` (the app's public key). We resolve
 * the owning app from that key and map each SDK event onto ApexHub's internal
 * analytics_events schema. The full original event is preserved under metadata.
 */
const router = Router()

// ── field mapping helpers ────────────────────────────────────────────────────

function extractApiKey(req: Request): string {
  const raw = (req.headers['authorization'] || req.headers['x-api-key'] || '').toString()
  return raw.replace(/^Bearer\s+/i, '').trim()
}

async function resolveApp(apiKey: string) {
  if (!apiKey) return null
  let app = await apps.findByPublicKey(apiKey)
  if (!app && apiKey.startsWith('pk_')) app = await apps.findByPublicKeyLike(apiKey)
  return app
}

/** Pull the device context regardless of nesting (context.device or top-level device). */
function getDevice(evt: any): Record<string, any> {
  if (evt?.context?.device && typeof evt.context.device === 'object') return evt.context.device
  if (evt?.device && typeof evt.device === 'object') return evt.device
  return {}
}

/** Map an open-analytics event to ApexHub's internal analytics row shape. */
function mapEvent(appId: string, evt: any) {
  const device = getDevice(evt)
  const eventName: string = evt.event_name || evt.event_type || 'custom'

  // Internal event_type drives dashboard aggregation:
  //   'session_start'/'app_launch' -> launches, 'crash' -> crashes.
  // Using the SDK event_name keeps "session_start" intact so opens are counted,
  // while custom/screen/error names stay human-readable in recent logs.
  const eventType = eventName

  // Derive a session duration for background events (ms -> s) when present.
  const foregroundMs = Number(evt?.properties?.time_in_foreground_ms)
  const sessionSec = Number.isFinite(foregroundMs) ? Math.round(foregroundMs / 1000) : 0

  return {
    id: uuid(),
    app_id: appId,
    event_type: eventType,
    event_name: eventName,
    // visitor_id is the SDK's persistent anonymous id — the right key for unique-device counts.
    device_id: String(evt.visitor_id || evt.device_id || ''),
    os_version: String(device.os || device.os_version || ''),
    device_model: String(device.model || device.device_model || ''),
    session_sec: sessionSec,
    metadata: {
      sdk_platform: evt.sdk_platform || 'android',
      sdk_version: evt.sdk_version,
      schema_version: evt.schema_version,
      wire_event_type: evt.event_type,
      event_id: evt.event_id,
      session_id: evt.session_id,
      user_id: evt.user_id,
      is_new_visitor: evt.is_new_visitor,
      screen_name: evt.screen_name,
      app_label: evt.app_id, // SDK config.appId (a label, not our UUID)
      device,
      properties: evt.properties || {},
      user_traits: evt.user_traits || {},
    },
  }
}

/** Map a crash report to an internal 'crash' analytics row. */
function mapCrash(appId: string, r: any) {
  const device = getDevice(r)
  return {
    id: uuid(),
    app_id: appId,
    event_type: 'crash',
    event_name: r.exception_class || 'crash',
    device_id: String(r.visitor_id || ''),
    os_version: String(device.os || ''),
    device_model: String(device.model || ''),
    session_sec: 0,
    metadata: {
      sdk_platform: r.sdk_platform || 'android',
      sdk_version: r.sdk_version,
      schema_version: r.schema_version,
      crash_id: r.crash_id,
      timestamp: r.timestamp,
      exception_class: r.exception_class,
      message: r.message,
      stack_trace: r.stack_trace,
      thread_name: r.thread_name,
      user_description: r.user_description,
      session_id: r.session_id,
      user_id: r.user_id,
      app_label: r.app_id,
      app_version_name: r.app_version_name,
      app_version_code: r.app_version_code,
      device,
    },
  }
}

// ── POST /api/v1/track ───────────────────────────────────────────────────────
router.post('/track', analyticsLimiter, async (req: Request, res: Response): Promise<void> => {
  const app = await resolveApp(extractApiKey(req))
  if (!app) {
    res.status(401).json({ error: 'Invalid or missing API key (Authorization: Bearer pk_...)' })
    return
  }

  const body = req.body || {}
  const events: any[] = Array.isArray(body.events) ? body.events : [body]
  if (events.length === 0) {
    res.status(200).json({ accepted: 0, accepted_ids: [] })
    return
  }

  const acceptedIds: string[] = []
  for (const evt of events) {
    try {
      const row = mapEvent(app.id, evt)
      await analytics.create(row)
      acceptedIds.push(evt.event_id || row.id)
    } catch (err: any) {
      console.error('[Ingest /track] event failed:', err?.message)
    }
  }

  res.status(200).json({ accepted: acceptedIds.length, accepted_ids: acceptedIds })
})

// ── POST /api/v1/crash-report ────────────────────────────────────────────────
router.post('/crash-report', analyticsLimiter, async (req: Request, res: Response): Promise<void> => {
  const app = await resolveApp(extractApiKey(req))
  if (!app) {
    res.status(401).json({ error: 'Invalid or missing API key (Authorization: Bearer pk_...)' })
    return
  }

  const body = req.body || {}
  const reports: any[] = Array.isArray(body.reports) ? body.reports : [body]
  if (reports.length === 0) {
    res.status(200).json({ accepted: 0, ids: [] })
    return
  }

  const ids: string[] = []
  for (const r of reports) {
    try {
      const row = mapCrash(app.id, r)
      await analytics.create(row)
      ids.push(r.crash_id || row.id)
    } catch (err: any) {
      console.error('[Ingest /crash-report] report failed:', err?.message)
    }
  }

  res.status(200).json({ accepted: ids.length, ids })
})

export default router
