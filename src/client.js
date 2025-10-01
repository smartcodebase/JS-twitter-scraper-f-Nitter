import crypto from 'crypto'
import OAuth from 'oauth-1.0a'
import { request } from 'undici'
import { gunzipSync, brotliDecompressSync, inflateSync } from 'zlib'
import puppeteer from 'puppeteer'

const GQL_BASE = 'https://api.x.com/graphql'
const WEB_GQL_BASE = 'https://x.com/i/api/graphql'
const WEB_BEARER = 'AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs=1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA'

// These endpoints mirror those defined in src/consts.nim. They may change over time.
export const ENDPOINTS = {
  userByScreenName: `${GQL_BASE}/u7wQyGi6oExe8_TRWGMq4Q/UserResultByScreenNameQuery`,
  userTweets: `${GQL_BASE}/JLApJKFY0MxGTzCoK6ps8Q/UserWithProfileTweetsQueryV2`,
  userTweetsAndReplies: `${GQL_BASE}/Y86LQY7KMvxn5tu3hFTyPg/UserWithProfileTweetsAndRepliesQueryV2`,
  userMedia: `${GQL_BASE}/PDfFf8hGeJvUCiTyWtw4wQ/MediaTimelineV2`,
  searchTimeline: `${GQL_BASE}/KI9jCXUx3Ymt-hDKLOZb9Q/SearchTimeline`,
  // Defaults for social graph (may rotate frequently; override via CLI if needed)
  following: `${GQL_BASE}/XKrIB4_YBx_J3JsUyDbruw/Following`,
  followers: `${GQL_BASE}/XKrIB4_YBx_J3JsUyDbruw/Followers`,
}

// Web (OAuth2 + cookies) endpoints for cases where OAuth1 fails
export const WEB_ENDPOINTS = {
  following: `${WEB_GQL_BASE}/XKrIB4_YBx_J3JsUyDbruw/Following`,
  followers: `${WEB_GQL_BASE}/XKrIB4_YBx_J3JsUyDbruw/Followers`,
}

export class XClient {
  constructor({ consumerKey, consumerSecret, oauthToken, oauthTokenSecret, sessionPool, webCredentials } = {}) {
    this.consumerKey = consumerKey
    this.consumerSecret = consumerSecret
    this.oauthToken = oauthToken
    this.oauthTokenSecret = oauthTokenSecret
    this.sessionPool = Array.isArray(sessionPool) ? sessionPool.slice() : null
    this.webCredentials = webCredentials // { username, password, otpSecret? }

    this.oauth = new OAuth({
      consumer: { key: consumerKey, secret: consumerSecret },
      signature_method: 'HMAC-SHA1',
      hash_function(base_string, key) {
        return crypto.createHmac('sha1', key).update(base_string).digest('base64')
      },
    })
  }

  pickSession() {
    if (!this.sessionPool || this.sessionPool.length === 0) {
      return { key: this.oauthToken, secret: this.oauthTokenSecret }
    }
    // simple random pick; could be improved with remaining counters
    const i = Math.floor(Math.random() * this.sessionPool.length)
    const s = this.sessionPool[i]
    return { key: s.oauth_token || s.oauthToken, secret: s.oauth_token_secret || s.oauthTokenSecret }
  }

  async get(url) {
    const { key, secret } = this.pickSession()
    const authHeader = this.oauth.toHeader(
      this.oauth.authorize({ url, method: 'GET' }, { key, secret })
    )

    const { statusCode, headers, body } = await request(url, {
      method: 'GET',
      headers: {
        ...authHeader,
        'accept': '*/*',
        'accept-encoding': 'gzip, br',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'connection': 'keep-alive',
        'DNT': '1',
        'authority': 'api.x.com',
      },
    })

    // Read raw bytes
    const buf = Buffer.from(await body.arrayBuffer())
    const enc = String(headers['content-encoding'] || headers['Content-Encoding'] || '').toLowerCase()

    let text
    try {
      if (enc === 'gzip') text = gunzipSync(buf).toString('utf8')
      else if (enc === 'br') text = brotliDecompressSync(buf).toString('utf8')
      else if (enc === 'deflate') text = inflateSync(buf).toString('utf8')
      else text = buf.toString('utf8')
    } catch (e) {
      // Fallback to utf8 if decompression fails
      text = buf.toString('utf8')
    }
    if (statusCode === 429 || text.startsWith('429 Too Many Requests')) {
      const err = new Error('RateLimited')
      err.statusCode = 429
      throw err
    }
    if (statusCode !== 200) {
      const err = new Error(`HTTP ${statusCode}: ${text}`)
      err.statusCode = statusCode
      err.responseText = text
      throw err
    }
    return text
  }

  async getJson(url) {
    const text = await this.get(url)
    try {
      return JSON.parse(text)
    } catch (e) {
      const err = new Error('Invalid JSON response')
      err.responseText = text
      throw err
    }
  }

  // ===== OAuth2 Web requests (require auth_token + ct0) =====
  async getWeb(url, { authToken, ct0 }) {
    if (!authToken || !ct0) throw new Error('authToken and ct0 are required for web requests')
    const { statusCode, headers, body } = await request(url, {
      method: 'GET',
      headers: {
        'authorization': `Bearer ${WEB_BEARER}`,
        'x-csrf-token': ct0,
        'x-twitter-auth-type': 'OAuth2Session',
        'x-twitter-active-user': 'yes',
        'content-type': 'application/json',
        'accept': '*/*',
        'accept-encoding': 'gzip, br',
        'accept-language': 'en-US,en;q=0.9',
        'cookie': `auth_token=${authToken}; ct0=${ct0}`,
      },
    })
    const buf = Buffer.from(await body.arrayBuffer())
    const enc = String(headers['content-encoding'] || headers['Content-Encoding'] || '').toLowerCase()
    let text
    try {
      if (enc === 'gzip') text = gunzipSync(buf).toString('utf8')
      else if (enc === 'br') text = brotliDecompressSync(buf).toString('utf8')
      else if (enc === 'deflate') text = inflateSync(buf).toString('utf8')
      else text = buf.toString('utf8')
    } catch {
      text = buf.toString('utf8')
    }
    if (statusCode !== 200) {
      const err = new Error(`HTTP ${statusCode}: ${text}`)
      err.statusCode = statusCode
      err.responseText = text
      throw err
    }
    return JSON.parse(text)
  }

  // Resolve a screen name to user object (contains rest_id)
  async getUserByScreenName(screenName) {
    const variables = JSON.stringify({ screen_name: screenName })
    const features = gqlFeatures()
    const url = `${ENDPOINTS.userByScreenName}?variables=${encodeURIComponent(variables)}&features=${encodeURIComponent(features)}`
    const data = await this.getJson(url)
    return data?.data?.user?.result
  }

  // Fetch timeline for a user by rest_id
  async getUserTweets(restId, { kind = 'tweets', cursor = '' } = {}) {
    const variables = { rest_id: restId, count: 20 }
    if (cursor) {
      // Unlike Nitter’s previous format, we simply add cursor via features supported by the endpoint
      variables.cursor = cursor
    }

    const endpoint =
      kind === 'media' ? ENDPOINTS.userMedia :
      kind === 'replies' ? ENDPOINTS.userTweetsAndReplies :
      ENDPOINTS.userTweets

    const url = `${endpoint}?variables=${encodeURIComponent(JSON.stringify(variables))}&features=${encodeURIComponent(gqlFeatures())}`
    return this.getJson(url)
  }

  // Fallback: use SearchTimeline with rawQuery `from:screenName`
  async getSearchTimelineByUser(screenName, { cursor = '' } = {}) {
    const variables = {
      rawQuery: `from:${screenName}`,
      count: 20,
      product: 'Latest',
      withDownvotePerspective: false,
      withReactionsMetadata: false,
      withReactionsPerspective: false,
    }
    if (cursor) variables.cursor = cursor
    const url = `${ENDPOINTS.searchTimeline}?variables=${encodeURIComponent(JSON.stringify(variables))}&features=${encodeURIComponent(gqlFeatures())}`
    return this.getJson(url)
  }

  // Generic helpers for followers/following via provided endpoint URLs
  async getUserFollowing(endpointUrl, restId, { cursor = '' } = {}) {
    if (!endpointUrl) throw new Error('Following endpoint URL is required')
    const variables = { userId: restId, count: 20 }
    if (cursor) variables.cursor = cursor
    const url = `${endpointUrl}?variables=${encodeURIComponent(JSON.stringify(variables))}&features=${encodeURIComponent(gqlFeatures())}`
    return this.getJson(url)
  }

  async getUserFollowers(endpointUrl, restId, { cursor = '' } = {}) {
    if (!endpointUrl) throw new Error('Followers endpoint URL is required')
    const variables = { userId: restId, count: 20 }
    if (cursor) variables.cursor = cursor
    const url = `${endpointUrl}?variables=${encodeURIComponent(JSON.stringify(variables))}&features=${encodeURIComponent(gqlFeatures())}`
    return this.getJson(url)
  }

  // Web variants using OAuth2 session cookies
  async getUserFollowingWeb(restId, { cursor = '', authToken, ct0 } = {}) {
    const variables = { userId: restId, count: 20, includePromotedContent: false, withGrokTranslatedBio: false }
    if (cursor) variables.cursor = cursor
    const url = `${WEB_ENDPOINTS.following}?variables=${encodeURIComponent(JSON.stringify(variables))}&features=${encodeURIComponent(webFeatures())}`
    return this.getWeb(url, { authToken, ct0 })
  }

  async getUserFollowersWeb(restId, { cursor = '', authToken, ct0 } = {}) {
    const variables = { userId: restId, count: 20, includePromotedContent: false, withGrokTranslatedBio: false }
    if (cursor) variables.cursor = cursor
    const url = `${WEB_ENDPOINTS.followers}?variables=${encodeURIComponent(JSON.stringify(variables))}&features=${encodeURIComponent(webFeatures())}`
    return this.getWeb(url, { authToken, ct0 })
  }

  // ===== Automatic cookie refresh via Puppeteer =====
  async getFreshWebCookies() {
    if (!this.webCredentials) {
      throw new Error('Web credentials required for automatic cookie refresh')
    }

    const browser = await puppeteer.launch({ 
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    })
    
    try {
      const page = await browser.newPage()
      await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36')
      
      // Go to login page
      await page.goto('https://x.com/login', { waitUntil: 'networkidle2' })
      
      // Enter username
      await page.waitForSelector('input[name="text"]', { timeout: 10000 })
      await page.type('input[name="text"]', this.webCredentials.username)
      await page.click('[role="button"]:has-text("Next")')
      
      // Wait for password field
      await page.waitForSelector('input[name="password"]', { timeout: 10000 })
      await page.type('input[name="password"]', this.webCredentials.password)
      await page.click('[data-testid="LoginForm_Login_Button"]')
      
      // Handle 2FA if needed
      if (this.webCredentials.otpSecret) {
        try {
          await page.waitForSelector('input[data-testid="ocfEnterTextTextInput"]', { timeout: 5000 })
          const { authenticator } = await import('otplib')
          const token = authenticator.generate(this.webCredentials.otpSecret)
          await page.type('input[data-testid="ocfEnterTextTextInput"]', token)
          await page.click('[data-testid="ocfEnterTextNextButton"]')
        } catch (e) {
          // No 2FA or already handled
        }
      }
      
      // Wait for successful login
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 30000 })
      
      // Extract cookies
      const cookies = await page.cookies()
      const authToken = cookies.find(c => c.name === 'auth_token')?.value
      const ct0 = cookies.find(c => c.name === 'ct0')?.value
      
      if (!authToken || !ct0) {
        throw new Error('Failed to extract auth_token or ct0 from cookies')
      }
      
      return { authToken, ct0 }
    } finally {
      await browser.close()
    }
  }

  // Auto-refresh wrapper for web operations
  async getUserFollowingWithRefresh(restId, { cursor = '', authToken, ct0 } = {}) {
    // If no authToken/ct0 provided, get fresh cookies first
    if (!authToken || !ct0) {
      if (!this.webCredentials) {
        throw new Error('Web credentials required for automatic cookie refresh')
      }
      console.error('Getting fresh web cookies...')
      const fresh = await this.getFreshWebCookies()
      return await this.getUserFollowingWeb(restId, { cursor, ...fresh })
    }
    
    try {
      return await this.getUserFollowingWeb(restId, { cursor, authToken, ct0 })
    } catch (e) {
      if (e.statusCode === 401 && this.webCredentials) {
        console.error('Web session expired, refreshing cookies...')
        const fresh = await this.getFreshWebCookies()
        return await this.getUserFollowingWeb(restId, { cursor, ...fresh })
      }
      throw e
    }
  }

  async getUserFollowersWithRefresh(restId, { cursor = '', authToken, ct0 } = {}) {
    // If no authToken/ct0 provided, get fresh cookies first
    if (!authToken || !ct0) {
      if (!this.webCredentials) {
        throw new Error('Web credentials required for automatic cookie refresh')
      }
      console.error('Getting fresh web cookies...')
      const fresh = await this.getFreshWebCookies()
      return await this.getUserFollowersWeb(restId, { cursor, ...fresh })
    }
    
    try {
      return await this.getUserFollowersWeb(restId, { cursor, authToken, ct0 })
    } catch (e) {
      if (e.statusCode === 401 && this.webCredentials) {
        console.error('Web session expired, refreshing cookies...')
        const fresh = await this.getFreshWebCookies()
        return await this.getUserFollowersWeb(restId, { cursor, ...fresh })
      }
      throw e
    }
  }

  // Attempt to find a user via People search and return the first matching rest_id
  async getUserBySearch(screenName, { cursor = '' } = {}) {
    const variables = {
      rawQuery: screenName,
      count: 20,
      product: 'People',
      withDownvotePerspective: false,
      withReactionsMetadata: false,
      withReactionsPerspective: false,
    }
    if (cursor) variables.cursor = cursor
    const url = `${ENDPOINTS.searchTimeline}?variables=${encodeURIComponent(JSON.stringify(variables))}&features=${encodeURIComponent(gqlFeatures())}`
    const data = await this.getJson(url)
    const instructions = data?.data?.search_by_raw_query?.search_timeline?.timeline?.instructions || []
    const entries = instructions.flatMap(i => i?.entries || [])
    for (const e of entries) {
      const u = e?.content?.itemContent?.user_results?.result
      const screen = u?.legacy?.screen_name
      if (u?.rest_id && screen && screen.toLowerCase() === screenName.toLowerCase()) {
        return { rest_id: u.rest_id, legacy: u.legacy }
      }
    }
    return null
  }
}

function gqlFeatures() {
  // Mirrors src/consts.nim:gqlFeatures (may need updates over time)
  return JSON.stringify({
    android_graphql_skip_api_media_color_palette: false,
    blue_business_profile_image_shape_enabled: false,
    creator_subscriptions_subscription_count_enabled: false,
    creator_subscriptions_tweet_preview_api_enabled: true,
    freedom_of_speech_not_reach_fetch_enabled: false,
    graphql_is_translatable_rweb_tweet_is_translatable_enabled: false,
    hidden_profile_likes_enabled: false,
    highlights_tweets_tab_ui_enabled: false,
    interactive_text_enabled: false,
    longform_notetweets_consumption_enabled: true,
    longform_notetweets_inline_media_enabled: false,
    longform_notetweets_richtext_consumption_enabled: true,
    longform_notetweets_rich_text_read_enabled: false,
    responsive_web_edit_tweet_api_enabled: false,
    responsive_web_enhance_cards_enabled: false,
    responsive_web_graphql_exclude_directive_enabled: true,
    responsive_web_graphql_skip_user_profile_image_extensions_enabled: false,
    responsive_web_graphql_timeline_navigation_enabled: false,
    responsive_web_media_download_video_enabled: false,
    responsive_web_text_conversations_enabled: false,
    responsive_web_twitter_article_tweet_consumption_enabled: false,
    responsive_web_twitter_blue_verified_badge_is_enabled: true,
    rweb_lists_timeline_redesign_enabled: true,
    spaces_2022_h2_clipping: true,
    spaces_2022_h2_spaces_communities: true,
    standardized_nudges_misinfo: false,
    subscriptions_verification_info_enabled: true,
    subscriptions_verification_info_reason_enabled: true,
    subscriptions_verification_info_verified_since_enabled: true,
    super_follow_badge_privacy_enabled: false,
    super_follow_exclusive_tweet_notifications_enabled: false,
    super_follow_tweet_api_enabled: false,
    super_follow_user_api_enabled: false,
    tweet_awards_web_tipping_enabled: false,
    tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled: false,
    tweetypie_unmention_optimization_enabled: false,
    unified_cards_ad_metadata_container_dynamic_card_content_query_enabled: false,
    verified_phone_label_enabled: false,
    vibe_api_enabled: false,
    view_counts_everywhere_api_enabled: false,
    premium_content_api_read_enabled: false,
    communities_web_enable_tweet_community_results_fetch: false,
    responsive_web_jetfuel_frame: false,
    responsive_web_grok_analyze_button_fetch_trends_enabled: false,
    responsive_web_grok_image_annotation_enabled: false,
    rweb_tipjar_consumption_enabled: false,
    profile_label_improvements_pcf_label_in_post_enabled: false,
    creator_subscriptions_quote_tweet_preview_enabled: false,
    c9s_tweet_anatomy_moderator_badge_enabled: false,
    responsive_web_grok_analyze_post_followups_enabled: false,
    rweb_video_timestamps_enabled: false,
    responsive_web_grok_share_attachment_enabled: false,
    articles_preview_enabled: false,
    immersive_video_status_linkable_timestamps: false,
    articles_api_enabled: false,
    responsive_web_grok_analysis_button_from_backend: false,
  })
}

function webFeatures() {
  return JSON.stringify({
    rweb_video_screen_enabled: false,
    payments_enabled: false,
    profile_label_improvements_pcf_label_in_post_enabled: true,
    rweb_tipjar_consumption_enabled: true,
    verified_phone_label_enabled: false,
    creator_subscriptions_tweet_preview_api_enabled: true,
    responsive_web_graphql_timeline_navigation_enabled: true,
    responsive_web_graphql_skip_user_profile_image_extensions_enabled: false,
    premium_content_api_read_enabled: false,
    communities_web_enable_tweet_community_results_fetch: true,
    c9s_tweet_anatomy_moderator_badge_enabled: true,
    responsive_web_grok_analyze_button_fetch_trends_enabled: false,
    responsive_web_grok_analyze_post_followups_enabled: true,
    responsive_web_jetfuel_frame: true,
    responsive_web_grok_share_attachment_enabled: true,
    articles_preview_enabled: true,
    responsive_web_edit_tweet_api_enabled: true,
    graphql_is_translatable_rweb_tweet_is_translatable_enabled: true,
    view_counts_everywhere_api_enabled: true,
    longform_notetweets_consumption_enabled: true,
    responsive_web_twitter_article_tweet_consumption_enabled: true,
    tweet_awards_web_tipping_enabled: false,
    responsive_web_grok_show_grok_translated_post: true,
    responsive_web_grok_analysis_button_from_backend: true,
    creator_subscriptions_quote_tweet_preview_enabled: false,
    freedom_of_speech_not_reach_fetch_enabled: true,
    standardized_nudges_misinfo: true,
    tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled: true,
    longform_notetweets_rich_text_read_enabled: true,
    longform_notetweets_inline_media_enabled: true,
    responsive_web_grok_image_annotation_enabled: true,
    responsive_web_grok_imagine_annotation_enabled: true,
    responsive_web_grok_community_note_auto_translation_is_enabled: false,
    responsive_web_enhance_cards_enabled: false,
  })
}


