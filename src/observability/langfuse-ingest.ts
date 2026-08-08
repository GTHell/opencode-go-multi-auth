/**
 * langfuse-ingest.ts — async (mode-2) telemetry for the multi-auth router.
 *
 * After each proxied request completes, the proxy enqueues a minimal
 * "generation" observation (token usage + latency + key metadata, NO
 * prompt/completion content). A background flusher batches events and POSTs
 * them to the self-hosted Langfuse instance. Failures are swallowed (logged
 * once per flush batch) — observability must never affect routing.
 */
import fs from 'node:fs'

const DEFAULT_BASE = 'http://127.0.0.1:3005'
const DEFAULT_SECRET_FILE = '/opt/langfuse/router-secret.txt'
const DEFAULT_PUBLIC_KEY = 'pk-lf-2b7e9d14-5f6a-4c8e-9b1d-3f5a7c9e2b41'

interface GenerationEvent {
  id: string
  traceId: string
  name: string
  model: string
  usage: {
    input: number
    output: number
    total: number
    inputCacheRead?: number
    inputCacheWrite?: number
    reasoning?: number
  }
  metadata: Record<string, unknown>
  startTime: string
  endTime: string
  level: 'DEFAULT' | 'WARNING' | 'ERROR' | 'DEBUG'
}

export interface LangfuseEmitArgs {
  keyId: string
  keyAlias: string
  workspaceId?: string | null
  model: string
  tokens: { input: number; output: number; total?: number; inputCacheRead?: number; inputCacheWrite?: number; reasoning?: number } | null
  cost: number | null
  durationMs: number
  statusCode: number
  sessionId: string | null
  startTime: number
  isZen: boolean
}

class LangfuseIngest {
  private readonly base: string
  private readonly auth: string
  private queue: GenerationEvent[] = []
  private flushTimer: NodeJS.Timeout | null = null
  private flushInFlight = false
  private readonly FLUSH_INTERVAL_MS = 5000
  private readonly MAX_BATCH = 20

  constructor(base = DEFAULT_BASE, publicKey = DEFAULT_PUBLIC_KEY, secretFile = DEFAULT_SECRET_FILE) {
    this.base = base
    let secret: string | null = null
    try {
      secret = fs.readFileSync(secretFile, 'utf8').trim()
    } catch {
      secret = process.env.LANGFUSE_ROUTER_SECRET ?? null
    }
    if (!secret) {
      // Observability is best-effort: no key, no telemetry.
      console.warn('[langfuse] no secret key found — telemetry disabled')
    }
    this.auth = secret ? `Basic ${Buffer.from(`${publicKey}:${secret}`).toString('base64')}` : ''
  }

  enabled(): boolean {
    return this.auth !== ''
  }

  enqueue(args: LangfuseEmitArgs): void {
    if (!this.enabled()) return
    const start = new Date(args.startTime)
    const end = new Date(args.startTime + args.durationMs)
    const tokens = args.tokens
    const event: GenerationEvent = {
      id: `${args.sessionId ?? 'gen'}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      traceId: args.sessionId ?? `router-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      name: `${args.isZen ? 'zen' : 'go'} ${args.model}`,
      model: args.model,
      usage: tokens
        ? {
            input: tokens.input ?? 0,
            output: tokens.output ?? 0,
            total: tokens.total ?? (tokens.input ?? 0) + (tokens.output ?? 0),
            inputCacheRead: tokens.inputCacheRead,
            inputCacheWrite: tokens.inputCacheWrite,
            reasoning: tokens.reasoning,
          }
        : { input: 0, output: 0, total: 0 },
      metadata: {
        keyId: args.keyId,
        keyAlias: args.keyAlias,
        workspaceId: args.workspaceId ?? null,
        statusCode: args.statusCode,
        cost: args.cost,
        upstream: args.isZen ? 'zen' : 'go',
      },
      startTime: start.toISOString(),
      endTime: end.toISOString(),
      level: args.statusCode >= 500 ? 'ERROR' : args.statusCode >= 400 ? 'WARNING' : 'DEFAULT',
    }
    this.queue.push(event)
    this.scheduleFlush()
  }

  private scheduleFlush(): void {
    if (this.flushTimer) return
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null
      void this.flush()
    }, this.FLUSH_INTERVAL_MS)
  }

  private async flush(): Promise<void> {
    if (this.flushInFlight || this.queue.length === 0) return
    this.flushInFlight = true
    const batch = this.queue.splice(0, this.MAX_BATCH)
    try {
      const body = JSON.stringify({
        batch: batch.map((ev) => ({
          id: ev.id,
          type: 'generation-create',
          timestamp: ev.startTime,
          body: ev,
        })),
      })
      const res = await fetch(`${this.base}/api/public/ingestion`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: this.auth },
        body,
      })
      const text = await res.text()
      if (!res.ok) {
        console.warn(`[langfuse] ingestion HTTP ${res.status}: ${text.slice(0, 200)}`)
      } else {
        try {
          const parsed = JSON.parse(text)
          const errs = Array.isArray(parsed?.errors) ? parsed.errors : []
          if (errs.length > 0) {
            console.warn(`[langfuse] ${errs.length}/${batch.length} events rejected: ${errs[0]?.message ?? ''}`.slice(0, 300))
          }
        } catch {
          /* non-JSON ok response — ignore */
        }
      }
    } catch (err) {
      // Best-effort: drop the batch rather than retry or block the router.
      console.warn(`[langfuse] flush failed: ${err instanceof Error ? err.message : String(err).slice(0, 120)}`)
    } finally {
      this.flushInFlight = false
      if (this.queue.length > 0) this.scheduleFlush()
    }
  }

  async shutdown(): Promise<void> {
    if (this.flushTimer) clearTimeout(this.flushTimer)
    this.flushTimer = null
    if (this.queue.length > 0) await this.flush()
  }
}

export const langfuseIngest = new LangfuseIngest()
