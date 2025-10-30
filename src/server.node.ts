import app from './index'
import { serve } from '@hono/node-server'

const port = Number(process.env.PORT || 12250)

console.log(`[TTS] Node server listening on http://localhost:${port}`)

serve({ fetch: app.fetch, port })
