import type { RuleOut } from '../../core/api/models';
import { isEscalation, isPending, isToggleable, pendingRules, registeredRules } from './admin.model';

const TOGGLEABLE: RuleOut = {
  rule_id: 't1-class-absent',
  tier: 1,
  version: '1',
  has_auto_determination_toggle: true,
  auto_determination_enabled: true,
  agreement_bar: 0.9,
  agreement_rate: 0.98,
  auto_suspended: false,
  volume_30d: 40,
};
const ESCALATION: RuleOut = {
  rule_id: 't3-epss',
  tier: 3,
  version: '1',
  has_auto_determination_toggle: false,
  volume_30d: 30,
};
const PENDING: RuleOut = { rule_id: 't1-cve-withdrawn', registered: false, reason: 'no evidence source' };

describe('admin.model', () => {
  describe('type guards', () => {
    it('isToggleable is true only for a rule with the toggle field set to true', () => {
      expect(isToggleable(TOGGLEABLE)).toBeTrue();
      expect(isToggleable(ESCALATION)).toBeFalse();
      expect(isToggleable(PENDING)).toBeFalse();
    });

    it('isEscalation is true only for a rule with the toggle field explicitly false', () => {
      expect(isEscalation(ESCALATION)).toBeTrue();
      expect(isEscalation(TOGGLEABLE)).toBeFalse();
      expect(isEscalation(PENDING)).toBeFalse();
    });

    it('isPending is true only when the toggle field is entirely absent', () => {
      expect(isPending(PENDING)).toBeTrue();
      expect(isPending(TOGGLEABLE)).toBeFalse();
      expect(isPending(ESCALATION)).toBeFalse();
    });
  });

  describe('registeredRules / pendingRules', () => {
    const all = [TOGGLEABLE, ESCALATION, PENDING];

    it('registeredRules never includes a pending rule', () => {
      const result: RuleOut[] = registeredRules(all);
      expect(result).toEqual([TOGGLEABLE, ESCALATION]);
    });

    it('pendingRules never includes a registered rule', () => {
      expect(pendingRules(all)).toEqual([PENDING]);
    });
  });
});
