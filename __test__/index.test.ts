import { Hoa } from 'hoa'
import { describe, it, expect, beforeEach } from '@jest/globals'
import { csrf } from '../src/index'
import { router } from '@hoajs/router'

describe('CSRF middleware', () => {
  describe('Safe methods (GET, HEAD, OPTIONS)', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(router())
    })

    it('Should allow GET requests without CSRF validation', async () => {
      app.get('/test', csrf(), (ctx) => {
        ctx.res.body = 'GET success'
      })
      const response = await app.fetch(new Request('http://localhost/test'))
      expect(response.status).toBe(200)
      expect(await response.text()).toBe('GET success')
    })

    it('Should allow HEAD requests without CSRF validation', async () => {
      app.head('/test', csrf(), (ctx) => {
        ctx.res.status = 200
        ctx.res.body = 'Hello Hoa'
      })
      const response = await app.fetch(new Request('http://localhost/test', { method: 'HEAD' }))
      const res = await response.text()
      expect(response.status).toBe(200)
      expect(res).toBe('')
      expect(response.headers.get('content-length')).toBe('9')
    })

    it('Should allow OPTIONS requests without CSRF validation', async () => {
      app.options('/test', csrf(), (ctx) => {
        ctx.res.body = 'OPTIONS success'
      })
      const response = await app.fetch(new Request('http://localhost/test', { method: 'OPTIONS' }))
      expect(response.status).toBe(200)
    })

    it('Should allow safe methods with Content-Type header without CSRF validation', async () => {
      app.get('/test-get', csrf(), (ctx) => {
        ctx.res.body = 'GET success'
      })
      app.head('/test-head', csrf(), (ctx) => {
        ctx.res.status = 200
      })
      app.options('/test-options', csrf(), (ctx) => {
        ctx.res.body = 'OPTIONS success'
      })

      // GET with Content-Type should not trigger CSRF validation
      const getResponse = await app.fetch(
        new Request('http://localhost/test-get', {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' }
        })
      )
      expect(getResponse.status).toBe(200)

      // HEAD with Content-Type should not trigger CSRF validation
      const headResponse = await app.fetch(
        new Request('http://localhost/test-head', {
          method: 'HEAD',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        })
      )
      expect(headResponse.status).toBe(200)

      // OPTIONS with Content-Type should not trigger CSRF validation
      const optionsResponse = await app.fetch(
        new Request('http://localhost/test-options', {
          method: 'OPTIONS',
          headers: { 'Content-Type': 'multipart/form-data' }
        })
      )
      expect(optionsResponse.status).toBe(200)
    })
  })

  describe('Unsafe methods (POST, PUT, DELETE, PATCH)', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(router())
    })

    it('Should block POST request without valid CSRF headers', async () => {
      app.post('/post', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })
      const response = await app.fetch(new Request('http://localhost/post', { method: 'POST' }))
      expect(response.status).toBe(403)
    })

    it('Should block PUT request without valid CSRF headers', async () => {
      app.put('/put', csrf(), (ctx) => {
        ctx.res.body = 'PUT success'
      })
      const response = await app.fetch(new Request('http://localhost/put', { method: 'PUT' }))
      expect(response.status).toBe(403)
    })

    it('Should block DELETE request without valid CSRF headers', async () => {
      app.delete('/del', csrf(), (ctx) => {
        ctx.res.body = 'DELETE success'
      })
      const response = await app.fetch(new Request('http://localhost/del', { method: 'DELETE' }))
      expect(response.status).toBe(403)
    })

    it('Should block PATCH request without valid CSRF headers', async () => {
      app.patch('/patch', csrf(), (ctx) => {
        ctx.res.body = 'PATCH success'
      })
      const response = await app.fetch(new Request('http://localhost/patch', { method: 'PATCH' }))
      expect(response.status).toBe(403)
    })
  })

  describe('Sec-Fetch-Site header validation', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(router())
    })

    it('Should allow POST with Sec-Fetch-Site: same-origin (default)', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })
      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'same-origin' }
        })
      )
      expect(response.status).toBe(200)
      expect(await response.text()).toBe('POST success')
    })

    it('Should block POST with Sec-Fetch-Site: cross-site (default)', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })
      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'cross-site' }
        })
      )
      expect(response.status).toBe(403)
    })

    it('Should allow POST with custom Sec-Fetch-Site string option', async () => {
      app.post('/test', csrf({ secFetchSite: 'same-site' }), (ctx) => {
        ctx.res.body = 'POST success'
      })
      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'same-site' }
        })
      )
      expect(response.status).toBe(200)
      expect(await response.text()).toBe('POST success')
    })

    it('Should allow POST with custom Sec-Fetch-Site array option', async () => {
      app.post('/test', csrf({ secFetchSite: ['same-origin', 'same-site'] }), (ctx) => {
        ctx.res.body = 'POST success'
      })
      const response1 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'same-origin' }
        })
      )
      expect(response1.status).toBe(200)
      const response2 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'same-site' }
        })
      )
      expect(response2.status).toBe(200)

      const response3 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'cross-site' }
        })
      )
      expect(response3.status).toBe(403)
    })

    it('Should allow POST with custom Sec-Fetch-Site function handler', async () => {
      app.post(
        '/test',
        csrf({
          secFetchSite: (secFetchSite, ctx) => {
            return secFetchSite === 'same-site' || secFetchSite === 'none'
          }
        }),
        (ctx) => {
          ctx.res.body = 'POST success'
        }
      )

      const response1 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'same-site' }
        })
      )
      expect(response1.status).toBe(200)

      const response2 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'none' }
        })
      )
      expect(response2.status).toBe(200)

      const response3 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'cross-site' }
        })
      )
      expect(response3.status).toBe(403)
    })

    it('Should block POST with invalid Sec-Fetch-Site value', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'invalid-value' }
        })
      )
      expect(response.status).toBe(403)
    })

    it('Should block POST without Sec-Fetch-Site header', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST'
        })
      )
      expect(response.status).toBe(403)
    })
  })

  describe('Origin header validation', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(router())
    })

    it('Should allow POST with matching Origin header (default)', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://localhost' }
        })
      )
      expect(response.status).toBe(200)
      expect(await response.text()).toBe('POST success')
    })

    it('Should block POST with non-matching Origin header (default)', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://evil.com' }
        })
      )
      expect(response.status).toBe(403)
    })

    it('Should allow POST with custom Origin string option', async () => {
      app.post('/test', csrf({ origin: 'http://trusted.com' }), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://trusted.com' }
        })
      )
      expect(response.status).toBe(200)
      expect(await response.text()).toBe('POST success')
    })

    it('Should allow POST with custom Origin array option', async () => {
      app.post('/test', csrf({ origin: ['http://trusted1.com', 'http://trusted2.com'] }), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response1 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://trusted1.com' }
        })
      )
      expect(response1.status).toBe(200)

      const response2 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://trusted2.com' }
        })
      )
      expect(response2.status).toBe(200)

      const response3 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://evil.com' }
        })
      )
      expect(response3.status).toBe(403)
    })

    it('Should allow POST with custom Origin function handler', async () => {
      app.post(
        '/test',
        csrf({
          origin: (origin, ctx) => {
            return origin.endsWith('.trusted.com') || origin === ctx.req.origin
          }
        }),
        (ctx) => {
          ctx.res.body = 'POST success'
        }
      )

      const response1 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://api.trusted.com' }
        })
      )
      expect(response1.status).toBe(200)

      const response2 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://localhost' }
        })
      )
      expect(response2.status).toBe(200)

      const response3 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://evil.com' }
        })
      )
      expect(response3.status).toBe(403)
    })

    it('Should block POST without Origin header', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST'
        })
      )
      expect(response.status).toBe(403)
    })
  })

  describe('Referer header validation', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(router())
    })

    it('Should allow POST with matching Referer header (default)', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Referer: 'http://localhost/page' }
        })
      )
      expect(response.status).toBe(200)
      expect(await response.text()).toBe('POST success')
    })

    it('Should block POST with non-matching Referer header', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Referer: 'http://evil.com/page' }
        })
      )
      expect(response.status).toBe(403)
    })

    it('Should block POST when checkReferer=false and other validations fail', async () => {
      app.post('/branch', csrf({ checkReferer: false }), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/branch', {
          method: 'POST',
          headers: {
            // Invalid Sec-Fetch-Site for default policy (expects same-origin)
            'Sec-Fetch-Site': 'cross-site'
            // No Origin header -> isAllowedOrigin returns false
          }
        })
      )

      expect(response.status).toBe(403)
    })

    it('Should block POST with invalid Referer URL format', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Referer: 'not-a-valid-url' }
        })
      )
      expect(response.status).toBe(403)
    })

    it('Should block POST without Referer header when checkReferer is true', async () => {
      app.post('/test', csrf({ checkReferer: true }), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST'
        })
      )
      expect(response.status).toBe(403)
    })

    it('Should allow POST with Referer when checkReferer is true and Referer matches', async () => {
      app.post('/test', csrf({ checkReferer: true }), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Referer: 'http://localhost/form' }
        })
      )
      expect(response.status).toBe(200)
      expect(await response.text()).toBe('POST success')
    })
  })

  describe('Content-Type validation', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(router())
    })

    it('Should validate default allowed content types', async () => {
      const defaultTypes = [
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'text/plain',
        'application/json',
        'application/xml',
        'text/xml'
      ]

      for (const contentType of defaultTypes) {
        const withoutSlashType = contentType.replace(/[^a-z]/g, '')
        app.post(`/test-${withoutSlashType}`, csrf(), (ctx) => {
          ctx.res.body = 'POST success'
        })

        const response = await app.fetch(
          new Request(`http://localhost/test-${withoutSlashType}`, {
            method: 'POST',
            headers: {
              'Content-Type': contentType,
              Origin: 'http://localhost'
            }
          })
        )
        expect(response.status).toBe(200)
      }
    })

    it('Should validate content type with charset', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            Origin: 'http://localhost'
          }
        })
      )
      expect(response.status).toBe(200)
    })

    it('Should skip CSRF validation for non-allowed content types', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream'
          }
        })
      )
      expect(response.status).toBe(200)
      expect(await response.text()).toBe('POST success')
    })

    it('Should allow custom allowedContentTypes option', async () => {
      app.post('/test', csrf({ allowedContentTypes: ['application/custom'] }), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response1 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/custom',
            Origin: 'http://localhost'
          }
        })
      )
      expect(response1.status).toBe(200)

      const response2 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          }
        })
      )
      expect(response2.status).toBe(200)

      const response3 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {}
        })
      )
      expect(response3.status).toBe(403)
    })

    it('Should validate POST without Content-Type header', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://localhost' }
        })
      )
      expect(response.status).toBe(200)
    })
  })

  describe('Multiple validation methods', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(router())
    })

    it('Should pass when any validation method succeeds', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response1 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            Origin: 'http://localhost',
            Referer: 'http://evil.com/page'
          }
        })
      )
      expect(response1.status).toBe(200)

      const response2 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            Origin: 'http://evil.com',
            Referer: 'http://localhost/page'
          }
        })
      )
      expect(response2.status).toBe(200)

      const response3 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            'Sec-Fetch-Site': 'same-origin',
            Origin: 'http://evil.com',
            Referer: 'http://evil.com/page'
          }
        })
      )
      expect(response3.status).toBe(200)
    })

    it('Should fail when all validation methods fail', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            'Sec-Fetch-Site': 'cross-site',
            Origin: 'http://evil.com',
            Referer: 'http://evil.com/page'
          }
        })
      )
      expect(response.status).toBe(403)
    })

    it('Should pass when multiple validation methods succeed', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            'Sec-Fetch-Site': 'same-origin',
            Origin: 'http://localhost',
            Referer: 'http://localhost/page'
          }
        })
      )
      expect(response.status).toBe(200)
      expect(await response.text()).toBe('POST success')
    })
  })

  describe('Edge cases', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(router())
    })

    it('Should handle case-insensitive HTTP methods', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'post',
          headers: { Origin: 'http://localhost' }
        })
      )
      expect(response.status).toBe(200)
    })

    it('Should handle empty string Content-Type', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            'Content-Type': '',
            Origin: 'http://localhost'
          }
        })
      )
      expect(response.status).toBe(200)
    })

    it('Should handle Referer with path and query parameters', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Referer: 'http://localhost/path/to/page?query=value#hash' }
        })
      )
      expect(response.status).toBe(200)
    })

    it('Should handle Referer with different port but same origin', async () => {
      app.post('/test', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Referer: 'http://localhost:8080/page' }
        })
      )
      expect(response.status).toBe(403)
    })

    it('Should handle Origin with port', async () => {
      app.post('/test', csrf({ origin: 'http://localhost:3000' }), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const response = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://localhost:3000' }
        })
      )
      expect(response.status).toBe(200)
    })

    it('Should handle all Sec-Fetch-Site values', async () => {
      const values = ['same-origin', 'same-site', 'none', 'cross-site']

      for (const value of values) {
        app.post(`/test-${value}`, csrf({ secFetchSite: value as any }), (ctx) => {
          ctx.res.body = 'POST success'
        })

        const response = await app.fetch(
          new Request(`http://localhost/test-${value}`, {
            method: 'POST',
            headers: { 'Sec-Fetch-Site': value }
          })
        )
        expect(response.status).toBe(200)
      }
    })

    it('Should call next middleware after successful validation', async () => {
      let middlewareCalled = false

      app.post(
        '/test',
        csrf(),
        async (ctx, next) => {
          middlewareCalled = true
          if (next) await next()
        },
        (ctx) => {
          ctx.res.body = 'POST success'
        }
      )

      await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://localhost' }
        })
      )

      expect(middlewareCalled).toBe(true)
    })

    it('Should not call next middleware when validation fails', async () => {
      let middlewareCalled = false

      app.post(
        '/test',
        csrf(),
        async (ctx, next) => {
          middlewareCalled = true
          if (next) await next()
        },
        (ctx) => {
          ctx.res.body = 'POST success'
        }
      )

      await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://evil.com' }
        })
      )

      expect(middlewareCalled).toBe(false)
    })
  })

  describe('Complex scenarios', () => {
    let app: Hoa

    beforeEach(() => {
      app = new Hoa()
      app.extend(router())
    })

    it('Should work with multiple routes and different configurations', async () => {
      app.post('/strict', csrf(), (ctx) => {
        ctx.res.body = 'Strict CSRF'
      })

      app.post('/lenient', csrf({ checkReferer: false, secFetchSite: ['same-origin', 'same-site'] }), (ctx) => {
        ctx.res.body = 'Lenient CSRF'
      })

      const strictResponse = await app.fetch(
        new Request('http://localhost/strict', {
          method: 'POST',
          headers: { Origin: 'http://localhost' }
        })
      )
      expect(strictResponse.status).toBe(200)

      const lenientResponse = await app.fetch(
        new Request('http://localhost/lenient', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'same-site' }
        })
      )
      expect(lenientResponse.status).toBe(200)
    })

    it('Should handle mixed safe and unsafe methods on same route', async () => {
      app.get('/resource', csrf(), (ctx) => {
        ctx.res.body = 'GET success'
      })

      app.post('/resource', csrf(), (ctx) => {
        ctx.res.body = 'POST success'
      })

      const getResponse = await app.fetch(new Request('http://localhost/resource'))
      expect(getResponse.status).toBe(200)
      expect(await getResponse.text()).toBe('GET success')

      const postResponse = await app.fetch(
        new Request('http://localhost/resource', {
          method: 'POST',
          headers: { Origin: 'http://localhost' }
        })
      )
      expect(postResponse.status).toBe(200)
      expect(await postResponse.text()).toBe('POST success')
    })

    it('Should work with custom origin handler accessing context', async () => {
      app.post(
        '/test',
        csrf({
          origin: (origin, ctx) => {
            return origin === ctx.req.origin || ctx.req.get('x-trusted') === 'true'
          }
        }),
        (ctx) => {
          ctx.res.body = 'POST success'
        }
      )

      const response1 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            Origin: 'http://evil.com',
            'X-Trusted': 'true'
          }
        })
      )
      expect(response1.status).toBe(200)

      const response2 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { Origin: 'http://localhost' }
        })
      )
      expect(response2.status).toBe(200)
    })

    it('Should work with custom secFetchSite handler accessing context', async () => {
      app.post(
        '/test',
        csrf({
          secFetchSite: (secFetchSite, ctx) => {
            return secFetchSite === 'same-origin' || ctx.req.get('x-bypass') === 'true'
          }
        }),
        (ctx) => {
          ctx.res.body = 'POST success'
        }
      )

      const response1 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: {
            'Sec-Fetch-Site': 'cross-site',
            'X-Bypass': 'true'
          }
        })
      )
      expect(response1.status).toBe(200)

      const response2 = await app.fetch(
        new Request('http://localhost/test', {
          method: 'POST',
          headers: { 'Sec-Fetch-Site': 'same-origin' }
        })
      )
      expect(response2.status).toBe(200)
    })
  })
})
