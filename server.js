require('dotenv').config()
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const express = require('express')
const axios = require('axios')
const { CookieJar } = require('tough-cookie')
const { wrapper } = require('axios-cookiejar-support')
const cors = require('cors')

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

app.get('/proxy/*path', async (req, res) => {
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
