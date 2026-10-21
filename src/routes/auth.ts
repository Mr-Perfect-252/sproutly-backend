import { Router, Request, Response } from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { v4 as uuid } from 'uuid'
import { z } from 'zod'
import { users } from '../store'
import { JWT_SECRET } from '../middleware/auth'
import { authLimiter } from '../middleware/rateLimiter'
import { validateBody } from '../middleware/validator'

const router = Router()

const SignupSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters').max(100),
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
})

const LoginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
})

// POST /api/auth/signup
router.post('/signup', authLimiter, validateBody(SignupSchema), async (req: Request, res: Response): Promise<void> => {
  const { name, email, password } = req.body

  const normalizedEmail = email.toLowerCase().trim()
  const existing = await users.findByEmail(normalizedEmail)
  if (existing) {
    res.status(409).json({ error: 'Email already in use' })
    return
  }

  const hashed = await bcrypt.hash(password, 12)
  const id = uuid()
  await users.create({ id, email: normalizedEmail, name: name.trim(), password: hashed })

  const token = jwt.sign({ userId: id, email: normalizedEmail }, JWT_SECRET, { expiresIn: '30d' })
  res.status(201).json({ token, user: { id, name: name.trim(), email: normalizedEmail, plan: 'free' } })
})

// POST /api/auth/login
router.post('/login', authLimiter, validateBody(LoginSchema), async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body

  const user = await users.findByEmail(email.toLowerCase().trim())
  if (!user) {
    res.status(401).json({ error: 'Invalid email or password' })
    return
  }

  const valid = await bcrypt.compare(password, user.password)
  if (!valid) {
    res.status(401).json({ error: 'Invalid email or password' })
    return
  }

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' })
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan } })
})

// GET /api/auth/me
router.get('/me', async (req: Request, res: Response): Promise<void> => {
  const header = req.headers.authorization
  if (!header?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Not authenticated' })
    return
  }
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET) as { userId: string; email?: string }
    let user: any = await users.findById(payload.userId)
    if (!user && payload.email) {
      user = await users.findByEmail(payload.email)
    }
    if (!user) {
      // Fallback: If JWT token is valid, construct session from token so a
      // brand-new (not-yet-persisted) developer identity does not drop auth state.
      const nameFromEmail = payload.email ? payload.email.split('@')[0] : 'Developer'
      user = { id: payload.userId, name: nameFromEmail, email: payload.email || 'developer@apexhub.app', plan: 'free' }
      await users.ensureExists({
        id: payload.userId,
        email: user.email,
        name: user.name,
        password: '$2a$12$dummyhashforjwtsessionrestoration',
      })
    }
    res.json({ user: { id: user.id, name: user.name, email: user.email, plan: user.plan || 'free', created_at: user.created_at } })
  } catch {
    res.status(401).json({ error: 'Invalid token' })
  }
})

export default router
