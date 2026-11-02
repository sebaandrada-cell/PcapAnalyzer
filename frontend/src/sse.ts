// Incremental parser for text/event-stream bodies read through fetch().
// EventSource cannot send an Authorization header, so the chat endpoint is
// consumed with fetch + ReadableStream and this parser turns the chunks into
// events. Pure module: `node --test src/sse.test.ts`.
export interface SseEvent {
  event: string
  data: unknown
}

export class SseParser {
  private tail = ''

  /** Feed a chunk; returns every complete event found so far. */
  push(chunk: string): SseEvent[] {
    this.tail += chunk.replace(/\r\n/g, '\n')
    const events: SseEvent[] = []
    let index = this.tail.indexOf('\n\n')
    while (index !== -1) {
      const frame = this.tail.slice(0, index)
      this.tail = this.tail.slice(index + 2)
      const parsed = parseFrame(frame)
      if (parsed) events.push(parsed)
      index = this.tail.indexOf('\n\n')
    }
    return events
  }

  /** At stream end: a last frame that was not followed by a blank line. */
  flush(): SseEvent[] {
    const frame = this.tail
    this.tail = ''
    const parsed = frame.trim() ? parseFrame(frame) : null
    return parsed ? [parsed] : []
  }
}

function parseFrame(frame: string): SseEvent | null {
  let event = 'message'
  const dataLines: string[] = []
  for (const line of frame.split('\n')) {
    if (line === '' || line.startsWith(':')) continue
    const colon = line.indexOf(':')
    const field = colon === -1 ? line : line.slice(0, colon)
    let value = colon === -1 ? '' : line.slice(colon + 1)
    if (value.startsWith(' ')) value = value.slice(1)
    if (field === 'event') event = value
    else if (field === 'data') dataLines.push(value)
  }
  if (dataLines.length === 0) return null
  try {
    return { event, data: JSON.parse(dataLines.join('\n')) }
  } catch {
    return null // a cut or malformed payload is dropped, never thrown
  }
}
