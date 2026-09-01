import { formatHours, formatPercent, percentWidth, rangeSince, segmentWidth } from './dashboard.model';

describe('dashboard.model', () => {
  describe('formatPercent', () => {
    it('formats a ratio as a rounded percentage', () => {
      expect(formatPercent(0.784)).toBe('78%');
    });
    it('never fabricates a value for null/undefined', () => {
      expect(formatPercent(null)).toBe('—');
      expect(formatPercent(undefined)).toBe('—');
    });
  });

  describe('formatHours', () => {
    it('formats sub-hour, hour and day ranges', () => {
      expect(formatHours(0.4)).toBe('<1h');
      expect(formatHours(3.2)).toBe('3.2h');
      expect(formatHours(72)).toBe('3.0d');
    });
    it('is "—" for null', () => {
      expect(formatHours(null)).toBe('—');
    });
  });

  describe('percentWidth', () => {
    it('clamps into [0, 100]', () => {
      expect(percentWidth(1.5)).toBe('100%');
      expect(percentWidth(-0.2)).toBe('0%');
      expect(percentWidth(0.5)).toBe('50%');
    });
    it('is 0% for null', () => {
      expect(percentWidth(null)).toBe('0%');
    });
  });

  describe('rangeSince', () => {
    it('subtracts the preset number of days from now', () => {
      const now = new Date('2026-09-01T12:00:00Z');
      expect(rangeSince(30, now)).toBe(new Date(now.getTime() - 30 * 24 * 3_600_000).toISOString());
    });
  });

  describe('segmentWidth', () => {
    it('is a percentage of the total', () => {
      expect(segmentWidth(3, 12)).toBe('25%');
    });
    it('is 0% rather than NaN% when the total is zero', () => {
      expect(segmentWidth(0, 0)).toBe('0%');
    });
  });
});
