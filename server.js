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

async function login() {
  console.log('[auth] Iniciando sesión...')

  // 1. GET login page → obtener CSRF token y cookies iniciales
  const loginPage = await axios.get(`${BASE_URL}/login`, {
    jar,
    withCredentials: true,
    headers: { 'User-Agent': 'Mozilla/5.0' },
  })

  const csrfMatch = loginPage.data.match(/name="_token"\s+value="([^"]+)"/)
  if (!csrfMatch) throw new Error('No se encontró el _token CSRF en la página de login')
  const csrfToken = csrfMatch[1]

  // Guardar cookies de la página de login en el jar
  const setCookies = loginPage.headers['set-cookie'] || []
  for (const cookie of setCookies) {
    await jar.setCookie(cookie, BASE_URL)
  }

  // 2. POST credenciales
  const body = new URLSearchParams({
    email: process.env.FACTURAOFITEC_EMAIL,
    password: process.env.FACTURAOFITEC_PASSWORD,
    _token: csrfToken,
  })

  const loginRes = await client.post('/login', body.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    maxRedirects: 5,
  })

  // Verificar que no quedamos en la página de login (credenciales inválidas)
  if (typeof loginRes.data === 'string' && loginRes.data.includes('Ingresa a tu cuenta')) {
    throw new Error('Credenciales inválidas para facturaofitec')
  }

  sessionValid = true
  console.log('[auth] Sesión iniciada correctamente')
}

async function ensureSession() {
  if (!sessionValid) await login()
}

function isHtmlResponse(data) {
  return typeof data === 'string' && data.trimStart().startsWith('<')
}

// ─── Express ────────────────────────────────────────────────────────────────

const app = express()

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
}))

app.use(express.json())

app.get('/health', (_req, res) => res.json({ ok: true, session: sessionValid }))

// Proxy: /proxy/reports/sales/records → oceans.facturaofitec.com/reports/sales/records
// Proxy: /proxy/api/documents/lists/...  → oceans.facturaofitec.com/api/documents/lists/...
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

    // Si devuelve HTML significa que la sesión expiró → re-login y retry
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
  // Login proactivo al arrancar
  login().catch((e) => console.error('[auth] Error en login inicial:', e.message))
})
