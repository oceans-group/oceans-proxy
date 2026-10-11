# oceans-proxy

Proxy entre [Oceans Analytics](https://github.com/oceans-group/oceans-group.github.io) y
facturaofitec. Mantiene una sesión con facturaofitec (login por formulario + cookies) y expone sus
endpoints de solo lectura al frontend, que se autentica con un token propio. Así las credenciales y el
token de facturaofitec nunca llegan al navegador.

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/health` | Estado del proxy y de la sesión con facturaofitec |
| POST | `/login` | `{ email, password }` → `{ token, expires_at }` (token firmado, 12 h). Máx. 5 fallos por IP cada 15 min |
| GET | `/proxy/*` | Reenvía el GET a facturaofitec. Requiere `Authorization: Bearer <token>`. Las rutas `/proxy/api/*` llevan además el token de API de facturaofitec |

Un 401 de facturaofitec se responde como **502**: el 401 queda reservado para "token de la app inválido",
que es lo que hace que el frontend cierre la sesión.

## Configuración

Requiere Node 22. Variables en `.env` (ver `.env.example`):

| Variable | Uso |
|---|---|
| `FACTURAOFITEC_EMAIL`, `FACTURAOFITEC_PASSWORD` | Cuenta de facturaofitec; también es el usuario de la app |
| `FACTURAOFITEC_TOKEN` | Token de la API de facturaofitec (rutas `/proxy/api/*`) |
| `AUTH_TOKEN_SECRET` | Firma de los tokens de la app (obligatorio) |
| `ALLOWED_ORIGIN` | Orígenes permitidos separados por coma. Si falta, solo `https://oceans-group.github.io` |
| `PORT` | Puerto (por defecto 3001) |

```sh
npm install
npm run dev   # node --watch
```

## TLS

oceans.facturaofitec.com no envía su certificado intermedio. En lugar de desactivar la verificación,
la cadena faltante está en `certs/facturaofitec-chain.pem` (Let's Encrypt YR2 + ISRG Root YR firmada
por ISRG Root X1). Si Let's Encrypt cambia el intermedio, las peticiones fallarán con
`UNABLE_TO_VERIFY_LEAF_SIGNATURE`: hay que agregar el nuevo intermedio a ese archivo (su URL está en
el campo "CA Issuers" del certificado del servidor). La solución de fondo es que facturaofitec sirva la
cadena completa.

## Despliegue

Render, con `npm start`. Desplegar el proxy antes que el frontend cuando un cambio del frontend
dependa de él.
