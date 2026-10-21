import { requireSupabase, nowEpoch, throwOnError } from './client'

export const githubStore = {
  async createOAuthState(input: { stateHash: string; userId: string; expiresAt: number }): Promise<void> {
    const supabase = requireSupabase()
    const { error: cleanupError } = await supabase
      .from('github_oauth_states')
      .delete()
      .lte('expires_at', nowEpoch())
    throwOnError(cleanupError, 'github.cleanupOAuthStates')
    const { error } = await supabase.from('github_oauth_states').insert({
      state_hash: input.stateHash,
      user_id: input.userId,
      expires_at: input.expiresAt,
      created_at: nowEpoch(),
    })
    throwOnError(error, 'github.createOAuthState')
  },

  async consumeOAuthState(stateHash: string): Promise<string | null> {
    const supabase = requireSupabase()
    const { data, error } = await supabase
      .from('github_oauth_states')
      .delete()
      .eq('state_hash', stateHash)
      .gt('expires_at', nowEpoch())
      .select('user_id')
      .maybeSingle()
    throwOnError(error, 'github.consumeOAuthState')
    return data?.user_id || null
  },

  async linkInstallation(input: {
    installationId: string
    userId: string
    accountId: string
    accountLogin: string
    accountType: string
    repositorySelection: string
    suspendedAt: string | null
  }): Promise<void> {
    const supabase = requireSupabase()
    const timestamp = nowEpoch()
    const { error } = await supabase.from('github_installations').upsert({
      installation_id: input.installationId,
      sproutly_user_id: input.userId,
      account_id: input.accountId,
      account_login: input.accountLogin,
      account_type: input.accountType,
      repository_selection: input.repositorySelection,
      suspended_at: input.suspendedAt,
      active: input.suspendedAt === null,
      updated_at: timestamp,
    }, { onConflict: 'installation_id' })
    throwOnError(error, 'github.linkInstallation')
  },

  async syncInstallationWebhook(installation: Record<string, unknown>, action: string): Promise<void> {
    const installationId = String(installation.id || '')
    if (!/^\d+$/.test(installationId)) {
      throw Object.assign(new Error('Webhook installation id is invalid'), { status: 400 })
    }

    const supabase = requireSupabase()
    const timestamp = nowEpoch()
    if (action === 'deleted') {
      const { error } = await supabase.from('github_installations')
        .update({ active: false, updated_at: timestamp })
        .eq('installation_id', installationId)
      throwOnError(error, 'github.syncInstallationWebhook')
      return
    }

    const account = installation.account as Record<string, unknown> | undefined
    const suspendedAt = typeof installation.suspended_at === 'string'
      ? installation.suspended_at
      : null
    const values = {
      account_id: String(account?.id || ''),
      account_login: String(account?.login || ''),
      account_type: String(account?.type || ''),
      repository_selection: String(installation.repository_selection || ''),
      suspended_at: suspendedAt,
      active: suspendedAt === null,
      updated_at: timestamp,
    }
    const { data, error: lookupError } = await supabase.from('github_installations')
      .select('installation_id')
      .eq('installation_id', installationId)
      .maybeSingle()
    throwOnError(lookupError, 'github.syncInstallationWebhook')

    if (data) {
      const { error } = await supabase.from('github_installations')
        .update(values)
        .eq('installation_id', installationId)
      throwOnError(error, 'github.syncInstallationWebhook')
      return
    }

    const { error } = await supabase.from('github_installations').insert({
      installation_id: installationId,
      ...values,
    })
    throwOnError(error, 'github.syncInstallationWebhook')
  },

  async recordWebhook(input: { deliveryId: string; eventName: string; payload: unknown }): Promise<void> {
    const supabase = requireSupabase()
    const { error } = await supabase.from('github_webhook_deliveries').upsert({
      delivery_id: input.deliveryId,
      event_name: input.eventName,
      payload: input.payload,
      received_at: nowEpoch(),
    }, { onConflict: 'delivery_id', ignoreDuplicates: true })
    throwOnError(error, 'github.recordWebhook')
  },
}
