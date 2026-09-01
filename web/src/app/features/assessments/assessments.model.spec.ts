import {
  ADMISSION_CHECK_LABEL,
  checkOrder,
  expiryBand,
  expiryClass,
  expiryLabel,
  extractReportId,
  formatRelativeAge,
  stateBadgeClass,
  stateLabel,
} from './assessments.model';

describe('assessments.model', () => {
  describe('stateBadgeClass / stateLabel', () => {
    it('upper-cases the wire value into the CSS class outcome.scss defines', () => {
      expect(stateBadgeClass('admission_failed')).toBe('state-pill state--ADMISSION_FAILED');
      expect(stateBadgeClass('needs_review')).toBe('state-pill state--NEEDS_REVIEW');
      expect(stateBadgeClass('completed')).toBe('state-pill state--COMPLETED');
    });

    it('renders a human label with underscores replaced', () => {
      expect(stateLabel('admission_failed')).toBe('admission failed');
      expect(stateLabel('needs_review')).toBe('needs review');
    });
  });

  describe('expiryBand', () => {
    const now = new Date('2026-09-01T12:00:00Z');

    it('is ok with no expires_at at all', () => {
      expect(expiryBand(null, now)).toBe('ok');
    });

    it('is ok more than 48 hours out', () => {
      const in72h = new Date(now.getTime() + 72 * 3_600_000).toISOString();
      expect(expiryBand(in72h, now)).toBe('ok');
    });

    it('is near at exactly the 48-hour boundary and inside it', () => {
      const in48h = new Date(now.getTime() + 48 * 3_600_000).toISOString();
      const in10h = new Date(now.getTime() + 10 * 3_600_000).toISOString();
      expect(expiryBand(in48h, now)).toBe('near');
      expect(expiryBand(in10h, now)).toBe('near');
    });

    it('is lapsed once the timestamp has passed', () => {
      const past = new Date(now.getTime() - 3_600_000).toISOString();
      expect(expiryBand(past, now)).toBe('lapsed');
    });
  });

  describe('expiryClass', () => {
    it('is the unadorned token for ok, and the named tokens otherwise', () => {
      expect(expiryClass('ok')).toBe('expiry');
      expect(expiryClass('near')).toBe('expiry expiry--near');
      expect(expiryClass('lapsed')).toBe('expiry expiry--lapsed');
    });
  });

  describe('expiryLabel', () => {
    const now = new Date('2026-09-01T12:00:00Z');

    it('counts down when in the future', () => {
      const in6d = new Date(now.getTime() + 6 * 24 * 3_600_000).toISOString();
      expect(expiryLabel(in6d, now)).toBe('expires in 6d');
    });

    it('reports how long ago it lapsed', () => {
      const past2d = new Date(now.getTime() - 2 * 24 * 3_600_000).toISOString();
      expect(expiryLabel(past2d, now)).toBe('determination lapsed 2d ago');
    });

    it('is empty with no expires_at', () => {
      expect(expiryLabel(null, now)).toBe('');
    });
  });

  describe('formatRelativeAge', () => {
    it('formats minutes, hours and days', () => {
      const now = new Date('2026-09-01T12:00:00Z');
      expect(formatRelativeAge(new Date(now.getTime() - 2 * 60_000).toISOString(), now)).toBe('2m ago');
      expect(formatRelativeAge(new Date(now.getTime() - 4 * 3_600_000).toISOString(), now)).toBe('4h ago');
      expect(formatRelativeAge(new Date(now.getTime() - 25 * 3_600_000).toISOString(), now)).toBe('1d ago');
    });
  });

  describe('ADMISSION_CHECK_LABEL / checkOrder', () => {
    it('names every check', () => {
      expect(ADMISSION_CHECK_LABEL.report).toContain('Report');
      expect(ADMISSION_CHECK_LABEL.artifact).toContain('Artifact');
      expect(ADMISSION_CHECK_LABEL.provenance).toContain('matches');
    });

    it('orders report, then artifact, then provenance — matching admission.py::admit', () => {
      expect(checkOrder('report')).toBeLessThan(checkOrder('artifact'));
      expect(checkOrder('artifact')).toBeLessThan(checkOrder('provenance'));
    });
  });

  describe('extractReportId', () => {
    it('passes a bare id through unchanged', () => {
      expect(extractReportId('38ef4d1f')).toBe('38ef4d1f');
    });

    it('extracts the trailing path segment from a full report URL', () => {
      expect(
        extractReportId('https://iq.example.com/assets/index.html#/applicationReport/payments-api/38ef4d1f'),
      ).toBe('38ef4d1f');
    });

    it('strips a trailing slash rather than returning an empty segment', () => {
      expect(extractReportId('https://iq.example.com/applicationReport/payments-api/38ef4d1f/')).toBe('38ef4d1f');
    });

    it('trims surrounding whitespace', () => {
      expect(extractReportId('  38ef4d1f  ')).toBe('38ef4d1f');
    });
  });
});
