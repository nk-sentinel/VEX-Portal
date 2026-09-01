/**
 * Verifies `tokens.scss` against `docs/design/ui-mockups.html` — the visual
 * authority. Every value below was transcribed independently from the
 * mockup (not copy-pasted from `tokens.scss`), so a drift in either file
 * shows up as a failing assertion here.
 *
 * Reads `getComputedStyle(document.documentElement).getPropertyValue(...)`.
 * The computed value of a CSS custom property is its specified text, not a
 * browser-normalised colour — confirmed empirically before writing this
 * spec — so a plain string comparison after `.trim()` is exact, with no
 * hex-vs-rgb() normalisation to worry about.
 *
 * `styles.scss` (which `@use`s `tokens.scss`) is loaded as a global style
 * for the Karma test build via `angular.json`'s `build.options.styles`, so
 * `:root` and `:root[data-theme="dark"]` are live on `document.documentElement`
 * for every spec in this suite.
 */

function token(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// Transcribed from the mockup's `:root { ... }` block (light).
const LIGHT: Record<string, string> = {
  '--space-1': '4px',
  '--space-2': '8px',
  '--space-3': '16px',
  '--space-4': '24px',
  '--space-5': '32px',
  '--space-6': '48px',
  '--space-7': '64px',

  '--bg-page': '#f4f6fb',
  '--bg-surface': '#ffffff',
  '--bg-surface-2': '#eaeef7',
  '--bg-hover': '#e6ebf5',
  '--bg-press': '#dbe2f0',
  '--bg-sidebar': '#0b101c',
  '--bg-sidebar-hover': '#18203a',
  '--bg-sidebar-active': '#2c3623',

  '--fg-primary': '#0d1424',
  '--fg-secondary': '#47536f',
  '--fg-muted': '#5a6782',
  '--fg-onAccent': '#070a12',
  '--fg-sidebar': '#94a3c0',
  '--fg-sidebar-active': '#ffffff',

  '--border-subtle': '#d5dcea',
  '--border-strong': '#a9b4cb',
  '--border-focus': '#586f00',
  '--border-sidebar': '#1e2940',

  '--accent': '#586f00',
  '--accent-hover': '#46590a',
  '--accent-fill': '#d8ff4a',
  '--accent-fill-hover': '#e6ff7a',
  '--accent-soft': '#eef8cf',
  '--accent-softer': '#f7fce9',

  '--success': '#1a7f37',
  '--success-soft': '#dafbe1',
  '--warning': '#9a6700',
  '--warning-soft': '#fff8c5',
  '--danger': '#cf222e',
  '--danger-soft': '#ffebe9',

  '--sev-critical': '#cf222e',
  '--sev-critical-soft': '#ffebe9',
  '--sev-high': '#b54708',
  '--sev-high-soft': '#fff4e5',
  '--sev-medium': '#9a6700',
  '--sev-medium-soft': '#fff8c5',
  '--sev-low': '#0969da',
  '--sev-low-soft': '#ddf4ff',
  '--sev-info': '#59636e',
  '--sev-info-soft': '#f2f4f7',

  '--radius-sm': '3px',
  '--radius-md': '6px',
  '--radius-lg': '8px',

  // VEX-SPECIFIC — outcome ramp (verdict hues).
  '--outcome-clear': '#1a7f37',
  '--outcome-clear-soft': '#dafbe1',
  '--outcome-affected': '#cf222e',
  '--outcome-affected-soft': '#ffebe9',
  '--outcome-review': '#b54708',
  '--outcome-review-soft': '#fff4e5',

  // VEX-SPECIFIC — hand-off, deliberately outside the outcome ramp.
  '--handoff': '#6639ba',
  '--handoff-soft': '#fbefff',
  '--handoff-border': '#c9a8f0',

  // VEX-SPECIFIC — evidence-tier ramp (authority, not severity).
  '--tier1': '#0e6b52',
  '--tier1-soft': '#d7f5ec',
  '--tier2': '#1f5d9e',
  '--tier2-soft': '#e0edfb',
  '--tier3': '#5a6782',
  '--tier3-soft': '#eaeef7',

  // VEX-SPECIFIC — escalation signals, deliberately colourless.
  '--signal-surface': '#eef1f8',
  '--signal-border': '#d5dcea',
  '--signal-fg': '#47536f',
  '--signal-label': '#5a6782',

  // VEX-SPECIFIC — assessment-state ramp.
  '--state-draft': '#59636e',
  '--state-draft-soft': '#f2f4f7',
  '--state-admission': '#0969da',
  '--state-admission-soft': '#ddf4ff',
  '--state-admission-failed': '#cf222e',
  '--state-admission-failed-soft': '#ffebe9',
  '--state-analysing': '#0969da',
  '--state-analysing-soft': '#ddf4ff',
  '--state-needs-review': '#b54708',
  '--state-needs-review-soft': '#fff4e5',
  '--state-awaiting-approval': '#6639ba',
  '--state-awaiting-approval-soft': '#fbefff',
  '--state-completed': '#1a7f37',
  '--state-completed-soft': '#dafbe1',
  '--state-expired': '#9a6700',
  '--state-expired-soft': '#fff8c5',

  // VEX-SPECIFIC — determination validity (expiry bands).
  '--expiry-ok': '#47536f',
  '--expiry-near': '#9a6700',
  '--expiry-near-soft': '#fff8c5',
  '--expiry-lapsed': '#cf222e',
  '--expiry-lapsed-soft': '#ffebe9',

  // VEX-SPECIFIC — rule trace.
  '--trace-rail': '#d5dcea',
  '--trace-pass': '#1a7f37',
  '--trace-neutral': '#5a6782',
  '--trace-hatch': '#b54708',
  '--trace-fail': '#cf222e',
};

// Transcribed from the mockup's `:root[data-theme="dark"] { ... }` block.
const DARK: Record<string, string> = {
  '--bg-page': '#070a12',
  '--bg-surface': '#101727',
  '--bg-surface-2': '#141d31',
  '--bg-sidebar': '#0b101c',
  '--bg-sidebar-active': '#2c3623',

  '--fg-primary': '#e8edf7',
  '--fg-secondary': '#94a3c0',
  '--fg-muted': '#7987a8',
  '--fg-onAccent': '#070a12',
  '--fg-sidebar': '#94a3c0',
  '--fg-sidebar-active': '#ffffff',

  '--border-subtle': '#1e2940',
  '--border-strong': '#2c3b5e',
  '--border-focus': '#d8ff4a',
  '--border-sidebar': '#1e2940',

  '--accent': '#d8ff4a',
  '--accent-hover': '#e6ff7a',
  '--accent-fill': '#d8ff4a',
  '--accent-fill-hover': '#e6ff7a',

  '--success': '#43e6a0',
  '--warning': '#ffd166',
  '--danger': '#ff5d6e',

  '--sev-critical': '#ff5d6e',
  '--sev-high': '#ff9e57',
  '--sev-medium': '#ffd166',
  '--sev-low': '#57a9ff',
  '--sev-info': '#94a3c0',

  // VEX-SPECIFIC (dark) — outcome ramp.
  '--outcome-clear': '#43e6a0',
  '--outcome-affected': '#ff5d6e',
  '--outcome-review': '#ff9e57',

  // VEX-SPECIFIC (dark) — hand-off.
  '--handoff': '#b78cff',
  '--handoff-soft': 'rgba(183, 140, 255, 0.14)',
  '--handoff-border': 'rgba(183, 140, 255, 0.45)',

  // VEX-SPECIFIC (dark) — evidence-tier ramp.
  '--tier1': '#43e6a0',
  '--tier2': '#57a9ff',
  '--tier3': '#94a3c0',

  // VEX-SPECIFIC (dark) — escalation signals.
  '--signal-fg': '#94a3c0',
  '--signal-label': '#7987a8',

  // VEX-SPECIFIC (dark) — assessment-state ramp.
  '--state-draft': '#94a3c0',
  '--state-admission': '#57d7ff',
  '--state-admission-failed': '#ff5d6e',
  '--state-analysing': '#57d7ff',
  '--state-needs-review': '#ff9e57',
  '--state-awaiting-approval': '#b78cff',
  '--state-completed': '#43e6a0',
  '--state-expired': '#ffd166',

  // VEX-SPECIFIC (dark) — expiry bands.
  '--expiry-ok': '#94a3c0',
  '--expiry-near': '#ffd166',
  '--expiry-lapsed': '#ff5d6e',

  // VEX-SPECIFIC (dark) — rule trace.
  '--trace-pass': '#43e6a0',
  '--trace-neutral': '#94a3c0',
  '--trace-hatch': '#ff9e57',
  '--trace-fail': '#ff5d6e',
};

describe('design tokens (docs/design/ui-mockups.html fidelity)', () => {
  afterEach(() => {
    document.documentElement.removeAttribute('data-theme');
  });

  describe('light (:root)', () => {
    for (const [name, expected] of Object.entries(LIGHT)) {
      it(`${name} = ${expected}`, () => {
        expect(token(name)).toBe(expected);
      });
    }
  });

  describe('dark (:root[data-theme="dark"])', () => {
    beforeEach(() => {
      document.documentElement.setAttribute('data-theme', 'dark');
    });

    for (const [name, expected] of Object.entries(DARK)) {
      it(`${name} = ${expected}`, () => {
        expect(token(name)).toBe(expected);
      });
    }
  });

  // --- The three load-bearing decisions called out in tokens.scss's header ---

  it('--handoff sits outside the outcome/verdict ramp (light)', () => {
    const handoff = token('--handoff');
    expect(handoff).not.toBe(token('--outcome-clear'));
    expect(handoff).not.toBe(token('--outcome-affected'));
    expect(handoff).not.toBe(token('--outcome-review'));
  });

  it('--handoff sits outside the outcome/verdict ramp (dark)', () => {
    document.documentElement.setAttribute('data-theme', 'dark');
    const handoff = token('--handoff');
    expect(handoff).not.toBe(token('--outcome-clear'));
    expect(handoff).not.toBe(token('--outcome-affected'));
    expect(handoff).not.toBe(token('--outcome-review'));
  });

  it('the escalation-signal block carries no severity/danger colour (light)', () => {
    // "Muted grey on a recessed surface" per ui-spec — never the red/orange
    // used for a severity or an Affected outcome, in either direction.
    expect(token('--signal-fg')).not.toBe(token('--danger'));
    expect(token('--signal-fg')).not.toBe(token('--sev-critical'));
    expect(token('--signal-fg')).not.toBe(token('--outcome-affected'));
    expect(token('--signal-surface')).not.toBe(token('--danger-soft'));
    expect(token('--signal-surface')).not.toBe(token('--sev-critical-soft'));
  });

  it('the escalation-signal block carries no severity/danger colour (dark)', () => {
    document.documentElement.setAttribute('data-theme', 'dark');
    expect(token('--signal-fg')).not.toBe(token('--danger'));
    expect(token('--signal-fg')).not.toBe(token('--sev-critical'));
    expect(token('--signal-fg')).not.toBe(token('--outcome-affected'));
  });

  it('has no token resembling a red-EPSS/severity-on-escalation colour', () => {
    // There is no such token in the design system at all — ui-spec: "no
    // red-EPSS token exists ... so no future change can accidentally place a
    // severity colour beside a Not Affected verdict." A few plausible names
    // a future edit might reach for; all must be genuinely absent (an
    // unset custom property computes to the empty string).
    for (const guess of ['--epss', '--epss-critical', '--sev-epss', '--escalation-critical', '--signal-danger']) {
      expect(token(guess)).toBe('');
    }
  });

  it('Tier 3 shares the escalation block\'s muted grey, not a severity colour (light)', () => {
    // "Tier 3 evidence and escalation signals are the same claim: routing,
    // never resolution" — ui-spec section 4. In the light palette --tier3
    // (#5a6782) is exactly --signal-label's muted grey, not a colour from
    // the outcome or severity ramps.
    expect(token('--tier3')).toBe(token('--signal-label'));
    expect(token('--tier3')).not.toBe(token('--outcome-clear'));
    expect(token('--tier3')).not.toBe(token('--outcome-affected'));
    expect(token('--tier3')).not.toBe(token('--sev-critical'));
  });

  it('Tier 3 shares the escalation block\'s muted grey, not a severity colour (dark)', () => {
    document.documentElement.setAttribute('data-theme', 'dark');
    // In the dark palette --tier3 (#94a3c0) is exactly --signal-fg's grey.
    expect(token('--tier3')).toBe(token('--signal-fg'));
    expect(token('--tier3')).not.toBe(token('--outcome-clear'));
    expect(token('--tier3')).not.toBe(token('--outcome-affected'));
    expect(token('--tier3')).not.toBe(token('--sev-critical'));
  });
});
