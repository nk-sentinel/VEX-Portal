import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';

import type { ReviewFindingDetail } from '../../core/api/models';
import { AuthService } from '../../core/auth/auth.service';
import { EvidenceDrawer } from './evidence-drawer';

/**
 * See the identical, more fully-explained helper in
 * `review-queue.spec.ts`: `whenStable()` waits for this component's
 * constructor `effect()` (the finding fetch) to fire and register its HTTP
 * call; the trailing `detectChanges()` is what actually repaints the DOM
 * once that async chain resolves (OnPush + a signal write does not itself
 * flush a new render — it needs a further change-detection pass).
 */
async function settle(fixture: ComponentFixture<unknown>): Promise<void> {
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
}

function detail(overrides: Partial<ReviewFindingDetail> = {}): ReviewFindingDetail {
  return {
    id: 'f1',
    assessment_id: 'asm-1',
    application_id: 'payments-api',
    cve: 'CVE-2023-20860',
    purl: 'pkg:maven/org.springframework/spring-web@5.3.26',
    threat_level: 8,
    outcome: 'needs_review',
    recommendation: {
      outcome: 'needs_review',
      reason: 'Routed to a human reviewer.',
      tier: null,
      justification: null,
      confidence: null,
      requires_second_confirmation: false,
    },
    rule_trace: [],
    escalation: {
      epss: 0.021,
      kev: false,
      cvss_base_score: 7.5,
      cvss_vector: 'AV:N/AC:L/PR:N/UI:N',
      fix_available: true,
      hard_blockers: [],
      note: 'not a basis for clearing',
    },
    ai_verdict: null,
    missing_evidence: [],
    determination: null,
    ...overrides,
  };
}

class FakeAuth {
  private readonly _username = signal('reviewer1');
  readonly username = this._username.asReadonly();
  private capabilities = new Set<string>(['recommend_determination']);
  hasCapability(capability: string): boolean {
    return this.capabilities.has(capability);
  }
  setCapabilities(caps: string[]): void {
    this.capabilities = new Set(caps);
  }
  setUsername(name: string): void {
    this._username.set(name);
  }
}

describe('EvidenceDrawer', () => {
  let httpMock: HttpTestingController;
  let auth: FakeAuth;
  // See the identical comment in `review-queue.spec.ts` — this component's
  // constructor effects (finding fetch, initial-focus) stay alive and keep
  // firing past the end of a test whose fixture is never destroyed.
  let fixtures: ComponentFixture<EvidenceDrawer>[];

  beforeEach(() => {
    auth = new FakeAuth();
    fixtures = [];
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), { provide: AuthService, useValue: auth }],
    });
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    fixtures.forEach((f) => f.destroy());
    httpMock.verify();
  });

  async function create(findingId = 'f1'): Promise<ComponentFixture<EvidenceDrawer>> {
    const fixture = TestBed.createComponent(EvidenceDrawer);
    fixtures.push(fixture);
    fixture.componentRef.setInput('findingId', findingId);
    await settle(fixture);
    return fixture;
  }

  async function flush(fixture: ComponentFixture<EvidenceDrawer>, body: ReviewFindingDetail): Promise<void> {
    httpMock.expectOne('/api/review/findings/f1').flush(body);
    await settle(fixture);
  }

  it('renders the recommendation and structurally separates escalation signals from the rule trace', async () => {
    const fixture = await create();
    await flush(fixture,
      detail({
        rule_trace: [{ rule_id: 't1-class-absent', rule_version: '1', tier: 1, verdict: 'not_satisfied', detail: {} }],
      }),
    );
    const el: HTMLElement = fixture.nativeElement;

    const signalsBlock = el.querySelector('.signals');
    expect(signalsBlock).withContext('escalation signals render as their own .signals block').not.toBeNull();
    expect(signalsBlock!.querySelector('.signals__disclaimer')!.textContent).toContain('not a basis for clearing');

    // Structural separation: no escalation fields inside the rule-trace block.
    const traceBlock = el.querySelector('.trace')!;
    expect(traceBlock.textContent).not.toContain('EPSS');
    expect(traceBlock.contains(signalsBlock)).toBe(false);
    expect(signalsBlock!.contains(traceBlock)).toBe(false);
  });

  it('shows the achieved tier as a sibling badge next to the outcome pill', async () => {
    const fixture = await create();
    await flush(fixture,
      detail({
        outcome: 'not_affected',
        recommendation: {
          outcome: 'not_affected',
          reason: 'Not affected.',
          tier: 1,
          justification: 'code_not_present',
          confidence: 'high',
          requires_second_confirmation: false,
        },
      }),
    );
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.tier--1')).not.toBeNull();
  });

  describe('Tier 2 second confirmation', () => {
    function tier2Detail(): ReviewFindingDetail {
      return detail({
        outcome: 'needs_review',
        recommendation: {
          outcome: 'needs_review',
          reason: 'Routed to a human reviewer.',
          tier: 2,
          justification: null,
          confidence: null,
          requires_second_confirmation: true,
        },
      });
    }

    it('shows the dashed second-confirmation strip once Not Affected is selected, naming that a confirmation is required', async () => {
      auth.setCapabilities(['recommend_determination', 'commit_determination']);
      const fixture = await create();
      await flush(fixture, tier2Detail());
      const component = fixture.componentInstance;

      expect(fixture.nativeElement.querySelector('.second-conf')).toBeNull();
      component.selectVerdict('not_affected');
      await settle(fixture);

      const strip = fixture.nativeElement.querySelector('.second-conf');
      expect(strip).withContext('Tier 2 clear must show the second-confirmation strip').not.toBeNull();
      expect(strip.textContent).toContain('second confirmation required');
    });

    it('cannot be saved without a distinct second confirmer when the session can commit', async () => {
      auth.setCapabilities(['recommend_determination', 'commit_determination']);
      auth.setUsername('approver1');
      const fixture = await create();
      await flush(fixture, tier2Detail());
      const component = fixture.componentInstance;

      component.selectVerdict('not_affected');
      (component as unknown as { justification: { set(v: string): void } }).justification.set('code_not_reachable');
      await settle(fixture);
      expect(fixture.nativeElement.querySelector('button.btn--primary').disabled).toBe(true);

      const confirmerInput: HTMLInputElement = fixture.nativeElement.querySelector('.second-conf input');
      confirmerInput.value = 'approver1'; // cannot confirm your own clear
      confirmerInput.dispatchEvent(new Event('input'));
      await settle(fixture);
      expect(fixture.nativeElement.querySelector('button.btn--primary').disabled).toBe(true);

      confirmerInput.value = 'reviewer2';
      confirmerInput.dispatchEvent(new Event('input'));
      await settle(fixture);
      expect(fixture.nativeElement.querySelector('button.btn--primary').disabled).toBe(false);
    });

    it('a reviewer without commit capability sees the strip as informational, no confirmer input', async () => {
      auth.setCapabilities(['recommend_determination']);
      const fixture = await create();
      await flush(fixture, tier2Detail());
      fixture.componentInstance.selectVerdict('not_affected');
      await settle(fixture);
      expect(fixture.nativeElement.querySelector('.second-conf input')).toBeNull();
    });
  });

  describe('abstention vs a failed collector — must look nothing alike', () => {
    it('renders the missing-evidence list as its own callout, distinct from any degraded-collector styling', async () => {
      const fixture = await create();
      await flush(fixture,
        detail({
          missing_evidence: ['no component-scanning configuration was available'],
          rule_trace: [{ rule_id: 't2-constant-pool', rule_version: '1', tier: 2, verdict: 'not_satisfied', detail: {} }],
        }),
      );
      const el: HTMLElement = fixture.nativeElement;

      const callouts = Array.from(el.querySelectorAll('.callout__title')).map((n) => n.textContent);
      expect(callouts).toContain('The adjudicator abstained — evidence missing');
      expect(callouts).not.toContain('Collector degraded');
      expect(el.querySelector('.trace__row--degraded')).toBeNull();
      expect(el.textContent).toContain('no component-scanning configuration was available');
    });

    it('renders a degraded collector as its own danger callout plus a marked trace row, with NO missing-evidence callout', async () => {
      const fixture = await create();
      await flush(fixture,
        detail({
          missing_evidence: [],
          rule_trace: [
            {
              rule_id: 't2-source-search',
              rule_version: '1',
              tier: 2,
              verdict: 'unanswerable',
              detail: { collector_status: 'failed', collector_error: 'Bitbucket DC timed out' },
            },
          ],
        }),
      );
      const el: HTMLElement = fixture.nativeElement;

      const callouts = Array.from(el.querySelectorAll('.callout__title')).map((n) => n.textContent);
      expect(callouts).toContain('Collector degraded');
      expect(callouts).not.toContain('The adjudicator abstained — evidence missing');
      expect(el.querySelector('.trace__row--degraded')).not.toBeNull();
      expect(el.textContent).toContain('Bitbucket DC timed out');
    });
  });

  it('a failed save keeps the reviewer input and does not close the drawer', async () => {
    const fixture = await create();
    await flush(fixture,
      detail({
        outcome: 'needs_review',
        recommendation: {
          outcome: 'needs_review',
          reason: 'x',
          tier: 1,
          justification: null,
          confidence: null,
          requires_second_confirmation: false,
        },
      }),
    );
    const component = fixture.componentInstance;
    let closedEmitted = false;
    component.closed.subscribe(() => (closedEmitted = true));

    component.selectVerdict('not_affected');
    (component as unknown as { justification: { set(v: string): void } }).justification.set('code_not_present');
    (component as unknown as { note: { set(v: string): void } }).note.set('a note worth keeping');
    await settle(fixture);

    void component['save']();
    const req = httpMock.expectOne('/api/review/findings/f1/recommend');
    req.flush({ detail: 'boom' }, { status: 500, statusText: 'Server Error' });
    await settle(fixture);

    expect(closedEmitted).toBe(false);
    expect((component as unknown as { note: { (): string } }).note()).toBe('a note worth keeping');
    expect(fixture.nativeElement.querySelector('.form-error')).not.toBeNull();
  });

  it('Escape closes the drawer', async () => {
    const fixture = await create();
    await flush(fixture, detail());
    let closedEmitted = false;
    fixture.componentInstance.closed.subscribe(() => (closedEmitted = true));

    fixture.nativeElement.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(closedEmitted).toBe(true);
  });

  it('traps focus: Tab from the last focusable element wraps to the first', async () => {
    const fixture = await create();
    await flush(fixture, detail());
    document.body.appendChild(fixture.nativeElement);

    const focusable = Array.from(
      fixture.nativeElement.querySelectorAll('button:not(:disabled), [href], input, select, textarea'),
    ) as HTMLElement[];
    expect(focusable.length).toBeGreaterThan(0);
    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    last.focus();
    const tabEvent = new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true });
    fixture.nativeElement.dispatchEvent(tabEvent);
    expect(document.activeElement).toBe(first);

    fixture.nativeElement.remove();
  });

  it('a Risk Acceptance Required finding renders the hand-off callout and no determination controls', async () => {
    const fixture = await create();
    await flush(fixture,
      detail({
        outcome: 'risk_acceptance_required',
        recommendation: {
          outcome: 'risk_acceptance_required',
          reason: 'No fix is available.',
          tier: null,
          justification: null,
          confidence: null,
          requires_second_confirmation: false,
        },
      }),
    );
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('.callout--handoff')).not.toBeNull();
    expect(el.querySelector('.callout--handoff')!.textContent).toContain('This left the portal');
    expect(el.querySelector('.radio-row')).toBeNull();
  });
});
