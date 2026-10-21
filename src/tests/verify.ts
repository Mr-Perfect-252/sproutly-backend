import assert from 'assert'
import { users, apps, reviews } from '../store'
import { getSupabase } from '../services/supabase'
import { generatePublicKey, generateSecretKey } from '../utils/keys'
import { malwareScanner } from '../services/scanner/malwareScanner'
import { storageService } from '../services/storage/storageService'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { JWT_SECRET } from '../middleware/auth'

async function runTests() {
  console.log('🚀 [Test Suite] Starting Apex Hub Verification Tests...\n')

  // 1. Test Key Generation
  const pk = generatePublicKey()
  const sk = generateSecretKey()
  assert(pk.startsWith('pk_live_'), 'Public key must start with pk_live_')
  assert(sk.startsWith('sk_live_'), 'Secret key must start with sk_live_')
  console.log('✔ [1/6] API Key Generator: PASSED')

  // 2. Test User Auth Hashing & JWT
  const testPassword = 'SecurePassword123!'
  const hashed = await bcrypt.hash(testPassword, 10)
  const isMatch = await bcrypt.compare(testPassword, hashed)
  assert(isMatch, 'Password hashing verification failed')

  const token = jwt.sign({ userId: 'test-user-1', email: 'dev@apkhub.com' }, JWT_SECRET, { expiresIn: '1h' })
  const decoded = jwt.verify(token, JWT_SECRET) as any
  assert.strictEqual(decoded.userId, 'test-user-1', 'JWT payload verification failed')
  console.log('✔ [2/6] Authentication & Password Hashing: PASSED')

  // 6. Malware Scanner & Storage Service (no DB needed — always run)
  const scanResult = await malwareScanner.scan('sample.apk', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  assert(scanResult.passed, 'Heuristic scan should pass valid apk extension')

  const downloadUrl = storageService.getDownloadUrl('https', 'cdn.apkhub.com', 'release-123', 'app.apk')
  assert(downloadUrl.includes('release-123'), 'Storage service URL formatting failed')
  console.log('✔ [6/6] Storage & Malware Scanner Pipeline: PASSED')

  // Database-backed tests require a configured Supabase instance.
  if (!getSupabase()) {
    console.log('\n⚠ Supabase not configured (SUPABASE_URL / key missing).')
    console.log('  Skipping DB persistence tests [3/6], [4/6], [5/6].')
    console.log('\n🎉 NON-DB VERIFICATION SUITES PASSED CLEANLY!\n')
    return
  }

  const testUserId = `test-user-${Date.now()}`
  const testEmail = `test_${Date.now()}@example.com`
  const testAppId = `app-${Date.now()}`
  const testPkg = `com.testapp.${Date.now()}`

  try {
    // 3. Test Database Operations (Supabase)
    await users.create({ id: testUserId, email: testEmail, name: 'Test Dev', password: hashed })
    const retrievedUser = await users.findById(testUserId)
    assert(retrievedUser, 'Failed to insert or query user')
    assert.strictEqual(retrievedUser!.email, testEmail)
    console.log('✔ [3/6] Database User Persistence: PASSED')

    // 4. Test App Creation & Public/Secret Keys
    await apps.create({
      id: testAppId, owner_id: testUserId, package_name: testPkg, name: 'TestApp',
      description: 'Description', category: 'Utilities', website_url: 'https://example.com',
      public_key: pk, secret_key: sk,
    })
    const retrievedApp = await apps.findByPackage(testPkg)
    assert(retrievedApp, 'Failed to insert app')
    assert.strictEqual(retrievedApp!.public_key, pk)
    console.log('✔ [4/6] App Registration & Keys Persistence: PASSED')

    // 5. Test Review Creation & Aggregation
    await reviews.create({ id: `rev-${Date.now()}`, app_id: testAppId, user_name: 'ReviewerOne', rating: 5, body: 'Great indie application!' })
    const owned = await apps.listByOwner(testUserId)
    const appWithReview = owned.find(a => a.id === testAppId)
    assert(appWithReview, 'App with review not found for owner')
    assert.strictEqual(appWithReview.review_count, 1)
    assert.strictEqual(appWithReview.avg_rating, 5)
    console.log('✔ [5/6] Review Submission & Rating Aggregation: PASSED')
  } finally {
    // Clean up test data so database stays pristine (cascades remove app + reviews)
    try { await apps.remove(testAppId) } catch {}
    try {
      const supabase = getSupabase()
      if (supabase) await supabase.from('users').delete().eq('id', testUserId)
    } catch {}
  }

  console.log('\n🎉 ALL 6 VERIFICATION TEST SUITES PASSED CLEANLY!\n')
}

runTests().catch(err => {
  console.error('\n❌ Test Suite Failed:', err)
  process.exit(1)
})
