// Matches Clerk user ids ("user_2abc...") and raw UUIDs — used to make sure
// an internal id never accidentally gets displayed as a developer's name.
const ID_LIKE = /^(user_[a-zA-Z0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i

export function isIdLike(value: string | undefined | null): boolean {
  const v = (value || '').trim()
  return !!v && ID_LIKE.test(v)
}

/** Returns the value only if it's a real display name, never a bare id. */
export function safeDisplayName(value: string | undefined | null, fallback = 'Developer'): string {
  const v = (value || '').trim()
  return v && !isIdLike(v) ? v : fallback
}
