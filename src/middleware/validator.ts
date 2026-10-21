import { Request, Response, NextFunction } from 'express'
import { ZodSchema, ZodError } from 'zod'

export function validateBody(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      req.body = schema.parse(req.body)
      next()
    } catch (err) {
      if (err instanceof ZodError) {
        res.status(400).json({
          error: 'Validation failed',
          details: err.issues.map((e: any) => ({ path: e.path.join('.'), message: e.message })),
        })
        return
      }
      next(err)
    }
  }
}

export function validateQuery(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      req.query = schema.parse(req.query) as any
      next()
    } catch (err) {
      if (err instanceof ZodError) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: err.issues.map((e: any) => ({ path: e.path.join('.'), message: e.message })),
        })
        return
      }
      next(err)
    }
  }
}
