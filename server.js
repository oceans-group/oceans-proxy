require('dotenv').config()
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const express = require('express')
const axios = require('axios')
const crypto = require('crypto')
const { CookieJar } = require('tough-cookie')
const { wrapper } = require('axios-cookiejar-support')
const cors = require('cors')

if (!process.env.AUTH_TOKEN_SECRET) {
  console.error('[auth] Falta AUTH_TOKEN_SECRET en el .env — es requerido para firmar los tokens de sesión del login.')
  process.exit(1)
}

const BASE_URL = 'https://oceans.facturaofitec.com'

const jar = new CookieJar()
const client = wrapper(
  axios.create({
    jar,
    baseURL: BASE_URL,
    withCredentials: true,
    headers: {
      'Accept': 'application/json, text/plain, */*',
      'X-Requested-With': 'XMLHttpRequest',
      'User-Agent': 'Mozilla/5.0',
    },
  }),
)

let sessionValid = false
let loginPromise = null

async function login() {
  console.log('[auth] Iniciando sesión...')

  const loginPage = await axios.get(`${BASE_URL}/login`, {
    jar,
    withCredentials: true,
    headers: { 'User-Agent': 'Mozilla/5.0' },
  })

  const csrfMatch = loginPage.data.match(/name="_token"\s+value="([^"]+)"/)
  if (!csrfMatch) throw new Error('No se encontró el _token CSRF en la página de login')
  const csrfToken = csrfMatch[1]

  const setCookies = loginPage.headers['set-cookie'] || []
  for (const cookie of setCookies) {
    await jar.setCookie(cookie, BASE_URL)
  }

  const body = new URLSearchParams({
    email: process.env.FACTURAOFITEC_EMAIL,
    password: process.env.FACTURAOFITEC_PASSWORD,
    _token: csrfToken,
  })

  const loginRes = await client.post('/login', body.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    maxRedirects: 5,
  })

  if (typeof loginRes.data === 'string' && loginRes.data.includes('Ingresa a tu cuenta')) {
    throw new Error('Credenciales inválidas para facturaofitec')
  }

  sessionValid = true
  console.log('[auth] Sesión iniciada correctamente')
}

async function ensureSession() {
  if (sessionValid) return
  if (!loginPromise) {
    loginPromise = login().finally(() => { loginPromise = null })
  }
  await loginPromise
}

function isHtmlResponse(data) {
  return typeof data === 'string' && data.trimStart().startsWith('<')
}

// ─── Login de la app (usuario/contraseña del .env → token de sesión) ─────────

const AUTH_TOKEN_TTL_MS = 12 * 60 * 60 * 1000 // 12h

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const sig = crypto.createHmac('sha256', process.env.AUTH_TOKEN_SECRET).update(body).digest('base64url')
  return `${body}.${sig}`
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null
  const [body, sig] = token.split('.')
  if (!body || !sig) return null

  const expectedSig = crypto.createHmac('sha256', process.env.AUTH_TOKEN_SECRET).update(body).digest('base64url')
  const sigBuf = Buffer.from(sig)
  const expectedBuf = Buffer.from(expectedSig)
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) return null

  let payload
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString())
  } catch {
    return null
  }
  if (!payload.exp || Date.now() > payload.exp) return null
  return payload
}

function timingSafeStringEqual(a, b) {
  const aBuf = Buffer.from(String(a ?? ''))
  const bBuf = Buffer.from(String(b ?? ''))
  if (aBuf.length !== bBuf.length) return false
  return crypto.timingSafeEqual(aBuf, bBuf)
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  const payload = verifyToken(token)
  if (!payload) return res.status(401).json({ error: 'No autorizado' })
  next()
}

// ─── Express ─────────────────────────────────────────────────────────────────

const app = express()

const allowedOrigins = (process.env.ALLOWED_ORIGIN || '*').split(',').map((o) => o.trim())

app.use(cors({
  origin: (origin, cb) => {
    if (allowedOrigins.includes('*') || !origin || allowedOrigins.includes(origin)) {
      cb(null, true)
    } else {
      cb(new Error(`Origen no permitido: ${origin}`))
    }
  },
}))

app.use(express.json())

app.get('/health', (_req, res) => res.json({ ok: true, session: sessionValid }))

app.post('/login', (req, res) => {
  const { email, password } = req.body || {}
  const validEmail = timingSafeStringEqual(email, process.env.FACTURAOFITEC_EMAIL)
  const validPassword = timingSafeStringEqual(password, process.env.FACTURAOFITEC_PASSWORD)

  if (!validEmail || !validPassword) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' })
  }

  const expires_at = Date.now() + AUTH_TOKEN_TTL_MS
  const token = signToken({ exp: expires_at })
  res.json({ token, expires_at })
})

app.get('/proxy/*path', requireAuth, async (req, res) => {
  const segments = req.params.path
  const path = '/' + (Array.isArray(segments) ? segments.join('/') : segments)

  try {
    await ensureSession()

    const extraHeaders = path.startsWith('/api/')
      ? { Authorization: `Bearer ${process.env.FACTURAOFITEC_TOKEN}` }
      : {}

    const response = await client.get(path, {
      params: req.query,
      headers: extraHeaders,
    })

    if (isHtmlResponse(response.data)) {
      console.log('[auth] Sesión expirada, re-autenticando...')
      sessionValid = false
      await login()
      const retry = await client.get(path, { params: req.query, headers: extraHeaders })
      return res.json(retry.data)
    }

    return res.json(response.data)
  } catch (err) {
    const status = err.response?.status
    if (status === 401 || status === 302) sessionValid = false
    console.error(`[error] ${path}:`, err.message)
    res.status(status || 500).json({ error: err.message })
  }
})

const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`Proxy corriendo en http://localhost:${PORT}`)
  login().catch((e) => console.error('[auth] Error en login inicial:', e.message))
})
