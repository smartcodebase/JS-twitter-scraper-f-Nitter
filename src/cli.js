#!/usr/bin/env node
import 'dotenv/config'
import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import { writeFile, readFile } from 'fs/promises'
import { XClient } from './client.js'

function getConfig() {
  const {
    X_CONSUMER_KEY,
    X_CONSUMER_SECRET,
    X_OAUTH_TOKEN,
    X_OAUTH_TOKEN_SECRET,
  } = process.env
  for (const [k, v] of Object.entries({ X_CONSUMER_KEY, X_CONSUMER_SECRET, X_OAUTH_TOKEN, X_OAUTH_TOKEN_SECRET })) {
    if (!v) throw new Error(`Missing env: ${k}`)
  }
  return {
    consumerKey: X_CONSUMER_KEY,
    consumerSecret: X_CONSUMER_SECRET,
    oauthToken: X_OAUTH_TOKEN,
    oauthTokenSecret: X_OAUTH_TOKEN_SECRET,
  }
}

async function main() {
  const argv = yargs(hideBin(process.argv))
    .command('$0 <username>', 'Fetch tweets for a screen name', y => y
      .positional('username', { type: 'string', describe: 'Screen name without @' })
      .option('kind', { type: 'string', choices: ['tweets', 'replies', 'media'], default: 'tweets', describe: 'Timeline kind' })
      .option('cursor', { type: 'string', describe: 'Pagination cursor' })
      .option('json', { type: 'boolean', default: true, describe: 'Print raw JSON' })
      .option('out', { type: 'string', describe: 'Write raw JSON to file path' })
      .option('sessions', { type: 'string', describe: 'Path to JSONL file of oauth_token pairs' })
      .option('followers', { type: 'boolean', describe: 'Fetch followers list (GraphQL)' })
      .option('following', { type: 'boolean', describe: 'Fetch following list (GraphQL)' })
      .option('followersEndpoint', { type: 'string', describe: 'Override Followers GraphQL URL (optional)' })
      .option('followingEndpoint', { type: 'string', describe: 'Override Following GraphQL URL (optional)' })
      .option('webAuthToken', { type: 'string', describe: 'Web cookie auth_token for OAuth2Session (optional fallback)' })
      .option('webCt0', { type: 'string', describe: 'Web cookie ct0 for OAuth2Session (optional fallback)' })
      .option('webUsername', { type: 'string', describe: 'X username for automatic cookie refresh (Option 2)' })
      .option('webPassword', { type: 'string', describe: 'X password for automatic cookie refresh (Option 2)' })
      .option('webOtpSecret', { type: 'string', describe: '2FA TOTP secret for automatic cookie refresh (optional)' })
    )
    .help()
    .parse()

  let sessionPool = null
  if (argv.sessions) {
    const text = await readFile(argv.sessions, 'utf8')
    sessionPool = text.split(/\r?\n/).filter(Boolean).map(line => {
      try { return JSON.parse(line) } catch { return null }
    }).filter(Boolean)
  }

  // Setup web credentials for automatic cookie refresh (Option 2)
  let webCredentials = null
  if (argv.webUsername && argv.webPassword) {
    webCredentials = {
      username: argv.webUsername,
      password: argv.webPassword,
      otpSecret: argv.webOtpSecret
    }
  }

  const client = new XClient({ ...getConfig(), sessionPool, webCredentials })
  let user = await client.getUserByScreenName(argv.username)
  if (!user || !user.rest_id) {
    // Try People search to resolve rest_id for very new accounts
    user = await client.getUserBySearch(argv.username)
  }
  let data
  if ((argv.followers || argv.following) && user && user.rest_id) {
    if (argv.followers) {
      const mod = await import('./client.js')
      const endpoint = argv.followersEndpoint || mod.ENDPOINTS.followers
      try {
        console.error('Trying OAuth1 API for followers...')
        data = await client.getUserFollowers(endpoint, user.rest_id, { cursor: argv.cursor })
        console.error('OAuth1 API succeeded')
      } catch (e) {
        console.error('OAuth1 API failed:', e.message)
        if (webCredentials) {
          // Option 2: Automatic cookie refresh
          console.error('Falling back to web authentication...')
          data = await client.getUserFollowersWithRefresh(user.rest_id, { cursor: argv.cursor })
        } else if (argv.webAuthToken && argv.webCt0) {
          // Option 1: Manual cookies
          console.error('Falling back to manual web cookies...')
          data = await client.getUserFollowersWeb(user.rest_id, { cursor: argv.cursor, authToken: argv.webAuthToken, ct0: argv.webCt0 })
        } else {
          console.error('No fallback options available. Please provide either:')
          console.error('1. OAuth credentials in .env file, or')
          console.error('2. Web credentials (--webUsername, --webPassword), or')
          console.error('3. Manual web cookies (--webAuthToken, --webCt0)')
          throw e
        }
      }
    } else {
      const mod = await import('./client.js')
      const endpoint = argv.followingEndpoint || mod.ENDPOINTS.following
      try {
        console.error('Trying OAuth1 API for following...')
        data = await client.getUserFollowing(endpoint, user.rest_id, { cursor: argv.cursor })
        console.error('OAuth1 API succeeded')
      } catch (e) {
        console.error('OAuth1 API failed:', e.message)
        if (webCredentials) {
          // Option 2: Automatic cookie refresh
          console.error('Falling back to web authentication...')
          data = await client.getUserFollowingWithRefresh(user.rest_id, { cursor: argv.cursor })
        } else if (argv.webAuthToken && argv.webCt0) {
          // Option 1: Manual cookies
          console.error('Falling back to manual web cookies...')
          data = await client.getUserFollowingWeb(user.rest_id, { cursor: argv.cursor, authToken: argv.webAuthToken, ct0: argv.webCt0 })
        } else {
          console.error('No fallback options available. Please provide either:')
          console.error('1. OAuth credentials in .env file, or')
          console.error('2. Web credentials (--webUsername, --webPassword), or')
          console.error('3. Manual web cookies (--webAuthToken, --webCt0)')
          throw e
        }
      }
    }
  } else if (user && user.rest_id) {
    data = await client.getUserTweets(user.rest_id, { kind: argv.kind, cursor: argv.cursor })
  } else {
    // Fallback to search timeline with from: query
    data = await client.getSearchTimelineByUser(argv.username, { cursor: argv.cursor })
  }
  if (argv.out) {
    await writeFile(argv.out, JSON.stringify(data, null, 2), 'utf8')
    console.error(`Saved JSON to ${argv.out}`)
  }

  if (argv.json) {
    console.log(JSON.stringify(data, null, 2))
  } else {
    // Print a compact summary from instructions-like structure
    const instructions = data?.data?.user?.result?.timeline_v2?.timeline?.instructions || []
    const entries = instructions.flatMap(i => i?.entries || [])
    for (const e of entries) {
      const t = e?.content?.itemContent?.tweet_results?.result || e?.content?.content?.tweetResult?.result
      if (!t) continue
      const id = t.rest_id
      const text = t.legacy?.full_text || t.note_tweet?.note_tweet_results?.result?.text || ''
      const user = t.core?.user_results?.result?.legacy?.screen_name || 'unknown'
      console.log(`@${user} — ${id}: ${text.replace(/\s+/g, ' ').slice(0, 160)}`)
    }
  }
}

main().catch(err => {
  console.error(err.message)
  if (err.responseText) {
    console.error(err.responseText)
  }
  process.exit(1)
})


