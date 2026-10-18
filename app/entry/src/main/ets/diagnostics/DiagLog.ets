/**
 * Turns `muharmony-native.log` into one entry per connection attempt.
 *
 * The native core starts every attempt with a marker line:
 *
 *   === connect 2026-10-18T03:49:19.000Z · Sweden · automatic ===
 *   +0.0s tunnel: starting to 185.65.134.1:51820
 *   +0.1s attempt se-sto-wg-001 (185.65.134.1)
 *   +0.4s tunnel: handshake complete
 *   +1.0s result: connected (se-sto-wg-001)
 *
 * Everything before the first marker belongs to older builds that wrote plain lines,
 * and is kept as a single legacy entry rather than being thrown away.
 */

export interface DiagEntry {
  id: string;
  /** Relay hostname, or the country label that was selected. */
  target: string;
  /** ISO timestamp from the marker; empty for the legacy entry. */
  startedAt: string;
  /** Local wall-clock label for the list. */
  startedLabel: string;
  /** connected | failed | stopped | incomplete | legacy */
  status: string;
  statusLabel: string;
  /** Short second line: what happened, or why it stopped. */
  summary: string;
  /** Elapsed seconds reported by the last log line, if any. */
  duration: string;
  attempts: number;
  body: string;
  lineCount: number;
}

function pad(value: number): string {
  return value < 10 ? `0${value}` : `${value}`;
}

/** `2026-10-18T03:49:19.000Z` → `10-18 11:49:19` in the device's zone. */
export function localStamp(iso: string): string {
  const at: number = Date.parse(iso);
  if (isNaN(at)) {
    return '';
  }
  const date = new Date(at);
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:` +
    `${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

/** Logs are written with a `+3.2s ` prefix inside a section; the message follows. */
function messageOf(line: string): string {
  if (line.startsWith('+')) {
    const space: number = line.indexOf(' ');
    if (space > 0) {
      return line.substring(space + 1);
    }
  }
  // Older builds prefixed lines with `[<epoch>] `.
  if (line.startsWith('[')) {
    const close: number = line.indexOf(']');
    if (close > 0) {
      return line.substring(close + 1).trim();
    }
  }
  return line;
}

function elapsedOf(line: string): string {
  if (!line.startsWith('+')) {
    return '';
  }
  const space: number = line.indexOf(' ');
  return space > 0 ? line.substring(1, space) : '';
}

function statusLabel(status: string): string {
  if (status === 'connected') {
    return 'Connected';
  }
  if (status === 'failed') {
    return 'Failed';
  }
  if (status === 'stopped') {
    return 'Stopped';
  }
  if (status === 'legacy') {
    return 'Legacy';
  }
  return 'Incomplete';
}

function buildEntry(id: string, title: string, startedAt: string, lines: string[]): DiagEntry {
  const body: string[] = [];
  let status: string = startedAt.length > 0 ? 'incomplete' : 'legacy';
  let summary: string = '';
  let duration: string = '';
  let attempts: number = 0;

  for (const line of lines) {
    if (line.trim().length === 0) {
      continue;
    }
    body.push(line);
    const message: string = messageOf(line);
    if (message.startsWith('attempt ')) {
      attempts += 1;
    }
    const elapsed: string = elapsedOf(line);
    if (elapsed.length > 0) {
      duration = elapsed;
    }
    if (message.startsWith('result: ')) {
      const result: string = message.substring('result: '.length);
      if (result.startsWith('connected')) {
        status = 'connected';
        const open: number = result.indexOf('(');
        const close: number = result.indexOf(')');
        const relay: string = open > 0 && close > open ? result.substring(open + 1, close) : '';
        summary = relay.length > 0 ? `Handshake with ${relay}` : 'Handshake completed';
      } else if (result.startsWith('failed')) {
        status = 'failed';
        const dot: number = result.indexOf('·');
        summary = dot > 0 ? result.substring(dot + 1).trim() : result;
      } else if (result.startsWith('stopped')) {
        status = 'stopped';
        summary = 'Disconnected';
      } else if (result.startsWith('connecting') && status === 'incomplete') {
        summary = 'Attempt did not finish';
      }
    }
  }

  if (summary.length === 0) {
    if (status === 'legacy') {
      summary = 'Lines written before diagnostics were sectioned';
    } else if (status === 'incomplete') {
      summary = 'No outcome recorded — the process stopped mid-attempt';
    }
  }
  if (status === 'connected' && attempts > 1) {
    summary = `Handshake completed after ${attempts} relays`;
  }

  return {
    id: id,
    target: title,
    startedAt: startedAt,
    startedLabel: startedAt.length > 0 ? localStamp(startedAt) : 'earlier builds',
    status: status,
    statusLabel: statusLabel(status),
    summary: summary,
    duration: duration,
    attempts: attempts,
    body: body.join('\n'),
    lineCount: body.length
  };
}

/** Newest section first: you look at the connection that just failed, not the first one. */
export function parseDiagLog(raw: string): DiagEntry[] {
  const entries: DiagEntry[] = [];
  if (raw.trim().length === 0) {
    return entries;
  }
  const lines: string[] = raw.split('\n');
  let title: string = 'Before diagnostics (legacy)';
  let startedAt: string = '';
  let buffer: string[] = [];
  let index: number = 0;

  const flush = () => {
    if (buffer.length === 0) {
      return;
    }
    entries.push(buildEntry(`entry-${index}`, title, startedAt, buffer));
    index += 1;
    buffer = [];
  };

  for (const line of lines) {
    if (line.startsWith('=== ') && line.trim().endsWith('===')) {
      flush();
      const inner: string = line.trim().substring(4, line.trim().length - 4).trim();
      const parts: string[] = inner.split(' · ');
      const head: string = parts.length > 0 ? parts[0] : inner;
      const rest: string = parts.length > 1 ? parts.slice(1).join(' · ') : '';
      if (head.startsWith('connect ')) {
        startedAt = head.substring('connect '.length).trim();
      } else {
        startedAt = '';
      }
      title = rest.length > 0 ? rest : 'Connection attempt';
    } else {
      buffer.push(line);
    }
  }
  flush();
  return entries.reverse();
}

/** Colour role for an entry's status, resolved by the caller. */
export function statusIsFailure(entry: DiagEntry): boolean {
  return entry.status === 'failed';
}

export function statusIsSuccess(entry: DiagEntry): boolean {
  return entry.status === 'connected';
}

/** Totals per status, for the filter chips above the diagnostics list. */
export interface DiagStatusCounts {
  connected: number;
  failed: number;
  stopped: number;
  incomplete: number;
  legacy: number;
}

/** Counts every entry once; unknown statuses are ignored. */
export function statusCounts(entries: DiagEntry[]): DiagStatusCounts {
  const counts: DiagStatusCounts = {
    connected: 0,
    failed: 0,
    stopped: 0,
    incomplete: 0,
    legacy: 0
  };
  for (const entry of entries) {
    if (entry.status === 'connected') {
      counts.connected += 1;
    } else if (entry.status === 'failed') {
      counts.failed += 1;
    } else if (entry.status === 'stopped') {
      counts.stopped += 1;
    } else if (entry.status === 'incomplete') {
      counts.incomplete += 1;
    } else if (entry.status === 'legacy') {
      counts.legacy += 1;
    }
  }
  return counts;
}
