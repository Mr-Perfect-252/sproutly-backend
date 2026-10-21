import rateLimit from 'express-rate-limit'

export const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
})

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 login/signup attempts per 15 mins per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts, please try again after 15 minutes.' },
})

export const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50, // 50 uploads per hour
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Upload rate limit exceeded, please try again in an hour.' },
})

export const inviteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many invitation attempts. Please try again later.' },
})

export const analyticsLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 1000, // 1000 events per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Analytics rate limit exceeded.' },
})
