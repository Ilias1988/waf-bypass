import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8')

test('production HTML has canonical SEO metadata and the configured analytics beacon', () => {
  const html = read('index.html')

  assert.match(html, /<html lang="en">/)
  assert.match(html, /<title>WAF Bypass Toolkit — Target-Aware Payload Transformer<\/title>/)
  assert.match(html, /<link rel="canonical" href="https:\/\/waf-bypass\.dev\/"/)
  assert.match(html, /static\.cloudflareinsights\.com\/beacon\.min\.js/)
  assert.match(html, /87302f99c9f54f118df9c640f907b7ba/)
  assert.doesNotMatch(html, /guarantee/i)
})

test('visible copy and structured data describe the product without universal bypass claims', () => {
  const intro = read('src/components/seo/ToolIntro.jsx')
  const seoHead = read('src/components/seo/SEOHead.jsx')
  const footer = read('src/components/layout/Footer.jsx')

  assert.match(intro, /not a guarantee/i)
  assert.match(intro, /does not send payloads to a target or execute them/i)
  assert.match(seoHead, /'@type': 'WebSite'/)
  assert.match(seoHead, /'@type': 'WebApplication'/)
  assert.match(seoHead, /Does this tool guarantee a WAF bypass\?/)
  assert.match(footer, /Payloads are transformed locally/i)
  assert.match(footer, /Cloudflare Web Analytics receives page-view and performance metrics/i)
})

test('release metadata and deploy helper preserve deliberate publication controls', () => {
  const packageJson = JSON.parse(read('package.json'))
  const packageLock = JSON.parse(read('package-lock.json'))
  const deploy = read('scripts/deploy-ghpages.mjs')

  assert.equal(packageJson.version, '1.1.0')
  assert.equal(packageLock.version, '1.1.0')
  assert.equal(packageLock.packages[''].version, '1.1.0')
  assert.match(deploy, /--confirm-deploy/)
  assert.match(deploy, /mkdtempSync/)
  assert.match(deploy, /spawnSync/)
  assert.match(deploy, /shell: false/)
  assert.match(deploy, /--force-with-lease/)
  assert.doesNotMatch(deploy, /_ghpages_tmp|execSync/)
})
