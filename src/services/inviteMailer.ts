import { spawn } from 'child_process'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { promisify } from 'util'

const mkdtemp = promisify(fs.mkdtemp)
const writeFile = promisify(fs.writeFile)
const removeDirectory = promisify(fs.rm)

function consoleBaseUrl(): string {
  const configured = process.env.PUBLIC_CONSOLE_URL || process.env.CONSOLE_URL || 'http://localhost:5173'
  let parsed: URL
  try {
    parsed = new URL(configured)
  } catch {
    throw new Error('PUBLIC_CONSOLE_URL must be a valid absolute URL')
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('PUBLIC_CONSOLE_URL must use HTTP or HTTPS')
  }
  return parsed.origin
}

export function testerInviteUrl(token: string): string {
  return `${consoleBaseUrl()}/dev-store/invite/${encodeURIComponent(token)}`
}

export async function sendTesterInvite(input: {
  email: string
  appName: string
  inviteUrl: string
}): Promise<void> {
  if (!process.env.COMPOSIO_KEY) {
    throw new Error('Email delivery is not configured. Set COMPOSIO_KEY on the backend.')
  }

  const tempDir = await mkdtemp(path.join(os.tmpdir(), 'sproutly-invite-'))
  const cliPath = path.resolve(__dirname, '../../node_modules/lanes-engine/bin/cli.js')
  const appName = input.appName.replace(/[\r\n]+/g, ' ').trim()
  const emailBody = [
    'Hello,',
    '',
    `You have been invited to test ${appName} in the Sproutly Development Store.`,
    'Accept the invitation to view and download development builds:',
    '{{invite_url}}',
    '',
    'This invitation expires in 7 days.',
  ].join('\n')

  try {
    await Promise.all([
      writeFile(path.join(tempDir, 'email.txt'), `Subject: You're invited to test ${appName}\n\n${emailBody}`, 'utf8'),
      writeFile(
        path.join(tempDir, 'senders.csv'),
        `email,invite_url\n${input.email},${input.inviteUrl}\n`,
        'utf8',
      ),
    ])

    await new Promise<void>((resolve, reject) => {
      const child = spawn(process.execPath, [cliPath, 'send', '--no-banner', '--lanes', '1'], {
        cwd: tempDir,
        env: { ...process.env, COMPOSIO_KEY: process.env.COMPOSIO_KEY },
        windowsHide: true,
        stdio: ['ignore', 'ignore', 'pipe'],
      })
      let stderr = ''
      const timeout = setTimeout(() => {
        child.kill()
        reject(new Error('Email delivery timed out after 90 seconds'))
      }, 90_000)
      child.stderr.setEncoding('utf8')
      child.stderr.on('data', (chunk: string) => { stderr = (stderr + chunk).slice(-2000) })
      child.once('error', error => {
        clearTimeout(timeout)
        reject(new Error(`Could not start lanes-engine: ${error.message}`))
      })
      child.once('close', code => {
        clearTimeout(timeout)
        if (code === 0) resolve()
        else reject(new Error(`lanes-engine email delivery failed (exit ${code ?? 'unknown'}). ${stderr.trim()}`))
      })
    })
  } finally {
    await removeDirectory(tempDir, { recursive: true, force: true })
  }
}
