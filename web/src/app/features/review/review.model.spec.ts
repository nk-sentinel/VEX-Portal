import type { ReviewFindingRow, RuleTraceEntry } from '../../core/api/models';
import {
  bulkBlockReason,
  bulkBlocks,
  degradedReason,
  formatAge,
  formatSla,
  groupByAssessment,
  isDegraded,
  justificationOptionsForTier,
  slaClass,
  sortRows,
  tierBadgeClass,
  tierLabel,
} from './review.model';

function row(overrides: Partial<ReviewFindingRow> = {}): ReviewFindingRow {
  return {
    id: 'f1',
    assessment_id: 'asm-1',
    application_id: 'payments-api',
    cve: 'CVE-2024-0001',
    purl: 'pkg:maven/x/y@1.0',
    outcome: 'needs_review',
    recommended_outcome: 'needs_review',
    tier: null,
    justification: null,
    confidence: null,
    sla_band: 'ok',
    sla_hours_remaining: 10,
    age_hours: 2,
    requester: 'requester1',
    decided_by: null,
    decided_at: null,
    ...overrides,
  };
}

describe('review.model', () => {
  describe('formatAge / formatSla', () => {
    it('formats sub-hour as <1h', () => expect(formatAge(0.4)).toBe('<1h'));
    it('formats hours', () => expect(formatAge(4.6)).toBe('5h'));
    it('formats days once >= 24h', () => expect(formatAge(50)).toBe('2d'));

    it('formats n/a SLA as an em dash', () => expect(formatSla('n/a', null)).toBe('—'));
    it('formats a breaching SLA with the "!" suffix', () => expect(formatSla('breaching', -3)).toBe('3h !'));
    it('formats an ok SLA with no suffix', () => expect(formatSla('ok', 10)).toBe('10h'));
  });

  describe('tier badge / label', () => {
    it('renders no badge class for a null tier', () => expect(tierBadgeClass(null)).toBeNull());
    it('renders a badge class per tier', () => expect(tierBadgeClass(2)).toBe('tier-badge tier--2'));
    it('renders an empty label for a null tier', () => expect(tierLabel(null)).toBe(''));
    it('renders "Tier N" otherwise', () => expect(tierLabel(1)).toBe('Tier 1'));
  });

  describe('slaClass', () => {
    it('breaching gets its own class', () => expect(slaClass('breaching')).toBe('sla sla--breach'));
    it('urgent gets its own class', () => expect(slaClass('urgent')).toBe('sla sla--soon'));
    it('ok/n-a stay plain', () => {
      expect(slaClass('ok')).toBe('sla');
      expect(slaClass('n/a')).toBe('sla');
    });
  });

  describe('justificationOptionsForTier', () => {
    it('offers nothing when no evidence tier was achieved', () => expect(justificationOptionsForTier(null)).toEqual([]));

    it('offers only code_not_present at tier 1', () => {
      expect(justificationOptionsForTier(1)).toEqual(['code_not_present']);
    });

    it('offers the four tier-2 justifications at tier 2, never code_not_present', () => {
      const options = justificationOptionsForTier(2);
      expect(options).toContain('code_not_reachable');
      expect(options).toContain('requires_dependency');
      expect(options).toContain('requires_configuration');
      expect(options).toContain('requires_environment');
      expect(options).not.toContain('code_not_present');
    });

    it('never offers perimeter/mitigating-control justifications at any tier, including 3', () => {
      for (const tier of [1, 2, 3] as const) {
        const options = justificationOptionsForTier(tier);
        expect(options).not.toContain('protected_at_perimeter');
        expect(options).not.toContain('protected_by_mitigating_control');
      }
    });
  });

  describe('sortRows', () => {
    it('sorts by SLA remaining ascending by default, nulls last', () => {
      const rows = [row({ id: 'a', sla_hours_remaining: 10 }), row({ id: 'b', sla_hours_remaining: null }), row({ id: 'c', sla_hours_remaining: 1 })];
      expect(sortRows(rows, 'sla', 'asc').map((r) => r.id)).toEqual(['c', 'a', 'b']);
    });

    it('reverses direction on desc', () => {
      const rows = [row({ id: 'a', age_hours: 1 }), row({ id: 'b', age_hours: 5 })];
      expect(sortRows(rows, 'age', 'desc').map((r) => r.id)).toEqual(['b', 'a']);
    });

    it('does not mutate the input array', () => {
      const rows = [row({ id: 'a', age_hours: 5 }), row({ id: 'b', age_hours: 1 })];
      const original = [...rows];
      sortRows(rows, 'age', 'asc');
      expect(rows).toEqual(original);
    });
  });

  describe('groupByAssessment', () => {
    it('preserves first-seen assessment order and keeps row order within a group', () => {
      const rows = [
        row({ id: 'a', assessment_id: 'asm-2', application_id: 'ledger-svc' }),
        row({ id: 'b', assessment_id: 'asm-1', application_id: 'payments-api' }),
        row({ id: 'c', assessment_id: 'asm-2', application_id: 'ledger-svc' }),
      ];
      const groups = groupByAssessment(rows);
      expect(groups.map((g) => g.assessmentId)).toEqual(['asm-2', 'asm-1']);
      expect(groups[0].rows.map((r) => r.id)).toEqual(['a', 'c']);
      expect(groups[0].applicationId).toBe('ledger-svc');
    });
  });

  describe('bulk-action eligibility', () => {
    it('blocks Risk Acceptance Required rows, naming why', () => {
      const reason = bulkBlockReason(row({ outcome: 'risk_acceptance_required' }));
      expect(reason).toContain('Risk Acceptance Required');
    });

    it('blocks needs_review rows — no safe bulk recommendation exists', () => {
      const reason = bulkBlockReason(row({ outcome: 'needs_review' }));
      expect(reason).toContain('routed to a human reviewer');
    });

    it('blocks a Tier 2 determination — must never be bulk-approved', () => {
      const reason = bulkBlockReason(row({ outcome: 'not_affected', tier: 2 }));
      expect(reason).toContain('Tier 2');
      expect(reason).toContain('individual second confirmation');
    });

    it('allows a Tier 1 not_affected row', () => {
      expect(bulkBlockReason(row({ outcome: 'not_affected', tier: 1 }))).toBeNull();
    });

    it('allows an affected row (no tier)', () => {
      expect(bulkBlockReason(row({ outcome: 'affected', tier: null }))).toBeNull();
    });

    it('bulkBlocks names every blocking CVE, not just the first', () => {
      const rows = [
        row({ id: 'a', cve: 'CVE-A', outcome: 'needs_review' }),
        row({ id: 'b', cve: 'CVE-B', outcome: 'not_affected', tier: 1 }),
        row({ id: 'c', cve: 'CVE-C', outcome: 'not_affected', tier: 2 }),
      ];
      const blocks = bulkBlocks(rows);
      expect(blocks.map((b) => b.cve)).toEqual(['CVE-A', 'CVE-C']);
    });
  });

  describe('degraded-collector detection (see this module for the "no live data source yet" note)', () => {
    function trace(detail: Record<string, unknown>): RuleTraceEntry {
      return { rule_id: 't2-source-search', rule_version: '1', tier: 2, verdict: 'unanswerable', detail };
    }

    it('is NOT degraded for a genuine abstention (evidence simply absent)', () => {
      expect(isDegraded(trace({ rule_verdict: 'unanswerable' }))).toBe(false);
    });

    it('IS degraded when detail carries collector_status: "failed"', () => {
      expect(isDegraded(trace({ rule_verdict: 'unanswerable', collector_status: 'failed' }))).toBe(true);
    });

    it('surfaces the collector_error text verbatim when present', () => {
      const reason = degradedReason(trace({ collector_status: 'failed', collector_error: 'Bitbucket DC timed out' }));
      expect(reason).toBe('Bitbucket DC timed out');
    });

    it('falls back to a generic outage sentence when no collector_error string is given', () => {
      const reason = degradedReason(trace({ collector_status: 'failed' }));
      expect(reason).toContain('did not respond');
    });
  });
});
