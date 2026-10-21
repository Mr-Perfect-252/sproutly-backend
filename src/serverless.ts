import app from './index'

export default function handler(req: any, res: any) {
  try {
    return app(req, res)
  } catch (err: any) {
    console.error('[Serverless Handler Error]:', err)
    if (!res.headersSent) {
      res.statusCode = 500
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({
        error: 'Internal Server Error',
        message: err?.message || String(err)
      }))
    }
  }
}
