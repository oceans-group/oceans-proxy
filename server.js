require('dotenv').config()

const express = require('express')
const axios = require('axios')
const crypto = require('crypto')
const fs = require('fs')
const tls = require('tls')
const { CookieJar } = require('tough-cookie')
const { HttpsCookieAgent } = require('http-cookie-agent/http')
const cors = require('cors')

if (!process.env.AUTH_TOKEN_SECRET) {
  console.error('[auth] Falta AUTH_TOKEN_SECRET en el .env — es requerido para firmar los tokens de sesión del login.')
  process.exit(1)
}

const BASE_URL = 'https://oceans.facturaofitec.com'

// facturaofitec no envía su certificado intermedio: se completa la cadena con certs/
// en lugar de desactivar la verificación TLS (ver el encabezado del .pem).
const jar = new CookieJar()
const httpsAgent = new HttpsCookieAgent({
  cookies: { jar },
  ca: [...tls.rootCertificates, fs.readFileSync(`${__dirname}/certs/facturaofitec-chain.pem`, 'utf8')],
})

const client = axios.create({
  baseURL: BASE_URL,
  httpsAgent,
  headers: {
    'Accept': 'application/json, text/plain, */*',
    'X-Requested-With': 'XMLHttpRequest',
    'User-Agent': 'Mozilla/5.0',
  },
})

let sessionValid = false
let loginPromise = null

async function login() {
  console.log('[auth] Iniciando sesión...')

  // Login siempre desde cero; las cookies nuevas (sesión + XSRF) las guarda el httpsAgent en el jar
  await jar.removeAllCookies()
  const loginPage = await axios.get(`${BASE_URL}/login`, {
    httpsAgent,
    headers: { 'User-Agent': 'Mozilla/5.0' },
  })

  const csrfMatch = loginPage.data.match(/name="_token"\s+value="([^"]+)"/)
  if (!csrfMatch) throw new Error('No se encontró el _token CSRF en la página de login')
  const csrfToken = csrfMatch[1]

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

// Render atiende detrás de un proxy: req.ip toma la IP real de X-Forwarded-For (un salto)
app.set('trust proxy', 1)

// Sin ALLOWED_ORIGIN solo se acepta el frontend publicado; '*' hay que configurarlo explícitamente
const DEFAULT_ORIGIN = 'https://oceans-group.github.io'
if (!process.env.ALLOWED_ORIGIN) console.warn(`[cors] Falta ALLOWED_ORIGIN en el .env — solo se acepta ${DEFAULT_ORIGIN}`)
const allowedOrigins = (process.env.ALLOWED_ORIGIN || DEFAULT_ORIGIN).split(',').map((o) => o.trim())

// Un origen no permitido no recibe cabeceras CORS y el navegador bloquea la respuesta
app.use(cors({
  origin: (origin, cb) => cb(null, allowedOrigins.includes('*') || !origin || allowedOrigins.includes(origin)),
}))

app.use(express.json())

app.get('/health', (_req, res) => res.json({ ok: true, session: sessionValid }))

// ─── Límite de intentos de login (en memoria: se reinicia con el proceso) ────

const LOGIN_MAX_FAILURES = 5
const LOGIN_WINDOW_MS = 15 * 60 * 1000
const loginFailures = new Map() // ip → { count, resetAt }

function loginBlockedUntil(ip) {
  const entry = loginFailures.get(ip)
  if (!entry) return 0
  if (Date.now() > entry.resetAt) {
    loginFailures.delete(ip)
    return 0
  }
  return entry.count >= LOGIN_MAX_FAILURES ? entry.resetAt : 0
}

function registerLoginFailure(ip) {
  const now = Date.now()
  const entry = loginFailures.get(ip)
  if (entry && now <= entry.resetAt) entry.count++
  else loginFailures.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS })
  if (loginFailures.size > 1000) {
    for (const [key, e] of loginFailures) if (now > e.resetAt) loginFailures.delete(key)
  }
}

app.post('/login', (req, res) => {
  const blockedUntil = loginBlockedUntil(req.ip)
  if (blockedUntil) {
    res.set('Retry-After', String(Math.ceil((blockedUntil - Date.now()) / 1000)))
    return res.status(429).json({ error: 'Demasiados intentos fallidos. Intenta de nuevo en unos minutos.' })
  }

  const { email, password } = req.body || {}
  const validEmail = timingSafeStringEqual(email, process.env.FACTURAOFITEC_EMAIL)
  const validPassword = timingSafeStringEqual(password, process.env.FACTURAOFITEC_PASSWORD)

  if (!validEmail || !validPassword) {
    registerLoginFailure(req.ip)
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' })
  }

  loginFailures.delete(req.ip)
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
    // Un 401 de facturaofitec no es un 401 de la app: si se reenvía, el frontend cierra la sesión del usuario
    res.status(status === 401 ? 502 : status || 500).json({ error: err.message })
  }
})

const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`Proxy corriendo en http://localhost:${PORT}`)
  login().catch((e) => console.error('[auth] Error en login inicial:', e.message))
})
