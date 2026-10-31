/**
 * Drift banner and stale-write advisory.
 *
 * Both answer "how far has the chain moved since this actor last oriented?"
 * from the flight recorder. The banner leads an orient response; the
 * advisory rides along on write responses. Neither blocks anything: the
 * server is observability, not authorization.
 *
 * Surfacing rule: EITHER threshold crossed (events OR elapsed time).
 */

export interface DriftRules {
  surface_at_events_since: number;
  surface_at_seconds_since: number;
}

export const DEFAULT_DRIFT_RULES: DriftRules = {
  surface_at_events_since: 100,
  surface_at_seconds_since: 4 * 60 * 60,
};

export interface DriftSignals {
  /** Chain events appended since the actor's last recorded orient; null = never oriented. */
  events_since_last_orient: number | null;
  /** Seconds since the actor's last recorded orient; null = never oriented. */
  seconds_since_last_orient: number | null;
}

export interface DriftBanner {
  surfaced: boolean;
  events_since_last_orient: number | null;
  seconds_since_last_orient: number | null;
  line: string;
}

export function composeDriftBanner(s: DriftSignals, rules: DriftRules = DEFAULT_DRIFT_RULES): DriftBanner {
  if (s.events_since_last_orient === null && s.seconds_since_last_orient === null) {
    return {
      surfaced: false,
      events_since_last_orient: null,
      seconds_since_last_orient: null,
      line: 'No prior orient recorded for this actor; first contact — treat everything below as new.',
    };
  }
  const eventsOver = s.events_since_last_orient !== null && s.events_since_last_orient >= rules.surface_at_events_since;
  const secondsOver =
    s.seconds_since_last_orient !== null && s.seconds_since_last_orient >= rules.surface_at_seconds_since;
  const surfaced = eventsOver || secondsOver;
  const events = s.events_since_last_orient ?? 0;
  const elapsed = formatElapsed(s.seconds_since_last_orient ?? 0);
  const line = surfaced
    ? `⚠️ ${events} ${plural(events, 'change', 'changes')} since your last orient ${elapsed} — you may be operating on stale assumptions; read the delta and retractions below before acting.`
    : `${events} ${plural(events, 'change', 'changes')} since your last orient ${elapsed} — within threshold.`;
  return {
    surfaced,
    events_since_last_orient: s.events_since_last_orient,
    seconds_since_last_orient: s.seconds_since_last_orient,
    line,
  };
}

export interface StaleWriteAdvisory {
  advisory: boolean;
  events_since_last_orient: number | null;
  seconds_since_last_orient: number | null;
  line: string | null;
}

/**
 * Advisory for a write made by an actor who may not have looked recently.
 * Never-oriented actors get an advisory too: they have no basis to know
 * what they are overwriting.
 */
export function composeStaleWriteAdvisory(
  s: DriftSignals,
  rules: DriftRules = DEFAULT_DRIFT_RULES,
): StaleWriteAdvisory {
  if (s.events_since_last_orient === null && s.seconds_since_last_orient === null) {
    return {
      advisory: true,
      events_since_last_orient: null,
      seconds_since_last_orient: null,
      line: 'Write accepted. This actor has never oriented; call get_system_state before further writes so you know what you are changing.',
    };
  }
  const banner = composeDriftBanner(s, rules);
  if (!banner.surfaced) {
    return {
      advisory: false,
      events_since_last_orient: s.events_since_last_orient,
      seconds_since_last_orient: s.seconds_since_last_orient,
      line: null,
    };
  }
  return {
    advisory: true,
    events_since_last_orient: s.events_since_last_orient,
    seconds_since_last_orient: s.seconds_since_last_orient,
    line: `Write accepted, but ${banner.line.replace(/^⚠️ /, '')} Consider re-orienting (get_system_state with your cursor) before the next write.`,
  };
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

export function formatElapsed(seconds: number): string {
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}
