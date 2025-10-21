import type { HoaContext, HoaMiddleware } from 'hoa'
import { HttpError } from 'hoa'

type IsAllowedOriginHandler = (origin: string, context: HoaContext) => boolean

const secFetchSiteValues = ['same-origin', 'same-site', 'none', 'cross-site'] as const
type SecFetchSite = (typeof secFetchSiteValues)[number]

const isSecFetchSite = (value: string): value is SecFetchSite =>
  (secFetchSiteValues as readonly string[]).includes(value)

type IsAllowedSecFetchSiteHandler = (secFetchSite: SecFetchSite, context: HoaContext) => boolean

interface CSRFOptions {
  origin?: string | string[] | IsAllowedOriginHandler
  secFetchSite?: SecFetchSite | SecFetchSite[] | IsAllowedSecFetchSiteHandler
  checkReferer?: boolean
  allowedContentTypes?: string[]
}

const isSafeMethodRe = /^(GET|HEAD|OPTIONS)$/

const DEFAULT_CONTENT_TYPES = [
  'application/x-www-form-urlencoded',
  'multipart/form-data',
  'text/plain',
  'application/json',
  'application/xml',
  'text/xml'
]

/**
 * CSRF Protection Middleware for Hoa.
 *
 * @param {CSRFOptions} [options] - The options for CSRF protection middleware.
 * @param {string|string[]|IsAllowedOriginHandler} [options.origin] -
 *   Allowed origins for requests.
 *   - `string`: Single allowed origin (e.g., 'https://example.com')
 *   - `string[]`: Multiple allowed origins
 *   - `function`: Custom validation logic with access to context
 *   - **Default**: Only same origin as the request URL (`ctx.req.origin`)
 * @param {SecFetchSite|SecFetchSite[]|IsAllowedSecFetchSiteHandler} [options.secFetchSite] -
 *   Sec-Fetch-Site header validation. Standard values: 'same-origin', 'same-site', 'cross-site', 'none'.
 *   - `string`: Single allowed value (e.g., 'same-origin')
 *   - `string[]`: Multiple allowed values (e.g., ['same-origin', 'same-site'])
 *   - `function`: Custom validation with access to context
 *   - **Default**: Only allows 'same-origin'
 * @param {boolean} [options.checkReferer=true] -
 *   Whether to validate the Referer header.
 *   - **Default**: `true` (validates that Referer origin matches request origin)
 *   - Set to `false` to skip Referer validation
 * @param {string[]} [options.allowedContentTypes] -
 *   Content-Types that require CSRF protection. Requests with other Content-Types skip validation.
 *   - **Default**: `['application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain', 'application/json', 'application/xml', 'text/xml']`
 *   - Use empty array `[]` to protect all Content-Types
 * @returns {HoaMiddleware} The middleware handler function
 * @throws {HttpError} 403 Forbidden when CSRF validation fails
 */
export function csrf (options: CSRFOptions = {}): HoaMiddleware {
  const {
    checkReferer = true,
    allowedContentTypes = DEFAULT_CONTENT_TYPES,
  } = options

  const originHandler: IsAllowedOriginHandler = ((optsOrigin) => {
    if (!optsOrigin) {
      return (origin, ctx) => origin === ctx.req.origin
    } else if (typeof optsOrigin === 'string') {
      return (origin) => origin === optsOrigin
    } else if (typeof optsOrigin === 'function') {
      return optsOrigin
    } else {
      return (origin) => optsOrigin.includes(origin)
    }
  })(options.origin)

  const secFetchSiteHandler: IsAllowedSecFetchSiteHandler = ((optsSecFetchSite) => {
    if (!optsSecFetchSite) {
      return (secFetchSite) => secFetchSite === 'same-origin'
    } else if (typeof optsSecFetchSite === 'string') {
      return (secFetchSite) => secFetchSite === optsSecFetchSite
    } else if (typeof optsSecFetchSite === 'function') {
      return optsSecFetchSite
    } else {
      return (secFetchSite) => optsSecFetchSite.includes(secFetchSite)
    }
  })(options.secFetchSite)

  const isAllowedOrigin = (origin: string | undefined, ctx: HoaContext) => {
    if (!origin) return false
    return originHandler(origin, ctx)
  }

  const isAllowedSecFetchSite = (secFetchSite: string | undefined, ctx: HoaContext) => {
    if (!secFetchSite) return false
    if (!isSecFetchSite(secFetchSite)) return false
    return secFetchSiteHandler(secFetchSite, ctx)
  }

  const isAllowedReferer = (referer: string | undefined, ctx: HoaContext) => {
    if (!referer) return false
    try {
      const refererUrl = new URL(referer)
      return refererUrl.origin === ctx.req.origin
    } catch {
      return false
    }
  }

  const needCSRFProtection = (method: string, contentType: string = '') => {
    if (isSafeMethodRe.test(method)) return false
    return !contentType || allowedContentTypes.some(type => contentType.includes(type))
  }

  return async function csrfMiddleware (ctx: HoaContext, next) {
    if (needCSRFProtection(ctx.req.method, ctx.req.type || '')) {
      const validationResults = {
        secFetchSite: isAllowedSecFetchSite(ctx.req.get('sec-fetch-site'), ctx),
        origin: isAllowedOrigin(ctx.req.get('origin'), ctx),
        referer: !checkReferer || isAllowedReferer(ctx.req.get('referer'), ctx)
      }
      if (!Object.values(validationResults).some(Boolean)) {
        throw new HttpError(403, 'CSRF validation failed')
      }
    }

    await next()
  }
}

export default csrf
