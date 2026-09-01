import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import type { RuleOut } from '../../core/api/models';
import { RulesAdmin } from './rules-admin';

async function settle(fixture: ComponentFixture<RulesAdmin>): Promise<void> {
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
}

const RULES: RuleOut[] = [
  {
    rule_id: 't1-class-absent',
    tier: 1,
    version: '1',
    has_auto_determination_toggle: true,
    auto_determination_enabled: true,
    agreement_bar: 0.9,
    agreement_rate: 0.98,
    auto_suspended: false,
    volume_30d: 40,
  },
  {
    rule_id: 't2-not-referenced',
    tier: 2,
    version: '1',
    has_auto_determination_toggle: true,
    auto_determination_enabled: false,
    agreement_bar: 0.9,
    agreement_rate: 0.6,
    auto_suspended: true,
    volume_30d: 12,
  },
  {
    rule_id: 't3-epss',
    tier: 3,
    version: '1',
    has_auto_determination_toggle: false,
    volume_30d: 30,
    thresholds: { hard_block_threshold: 0.1 },
  },
  { rule_id: 't1-cve-withdrawn', registered: false, reason: 'CVE lifecycle status not yet carried' },
  { rule_id: 't2-gadget-absent', registered: false, reason: 'gadget knowledge not yet cached' },
  { rule_id: 't2-runtime-immune', registered: false, reason: 'runtime version not collected' },
];

describe('RulesAdmin', () => {
  let httpMock: HttpTestingController;
  let fixtures: ComponentFixture<RulesAdmin>[];

  function setUp() {
    fixtures = [];
    TestBed.configureTestingModule({ providers: [provideHttpClient(), provideHttpClientTesting()] });
    httpMock = TestBed.inject(HttpTestingController);
  }

  async function create(): Promise<ComponentFixture<RulesAdmin>> {
    setUp();
    const fixture = TestBed.createComponent(RulesAdmin);
    fixtures.push(fixture);
    await settle(fixture);
    return fixture;
  }

  afterEach(() => {
    fixtures.forEach((f) => f.destroy());
    httpMock.verify();
  });

  it('loading state', () => {
    setUp();
    const fixture = TestBed.createComponent(RulesAdmin);
    fixtures.push(fixture);
    fixture.detectChanges();
    expect(fixture.componentInstance['pageState']()).toBe('loading');
    httpMock.expectOne('/api/admin/rules').flush([]);
  });

  it('error state offers a retry', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/admin/rules').flush({ detail: 'boom' }, { status: 500, statusText: 'Server Error' });
    await settle(fixture);
    expect(fixture.componentInstance['pageState']()).toBe('error');

    fixture.componentInstance['retry']();
    httpMock.expectOne('/api/admin/rules').flush(RULES);
    await settle(fixture);
    expect(fixture.componentInstance['pageState']()).toBe('normal');
  });

  it('a Tier 3 rule renders NO toggle at all — not a disabled one', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/admin/rules').flush(RULES);
    await settle(fixture);

    const html = (fixture.nativeElement as HTMLElement).innerHTML;
    // The escalation row's own note text is present...
    expect(html).toContain('no auto-determination capability');
    // ...and there is no chip/button element rendered for that row's toggle cell.
    const rows = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('tbody tr'));
    const epssRow = rows.find((r) => r.textContent?.includes('t3-epss'));
    expect(epssRow?.querySelector('button.chip')).toBeNull();
  });

  it('a Tier 1/2 rule DOES render a toggle, and clicking it flips the value', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/admin/rules').flush(RULES);
    await settle(fixture);

    const rows = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('tbody tr'));
    const row = rows.find((r) => r.textContent?.includes('t1-class-absent'));
    const toggle = row?.querySelector('button.chip') as HTMLButtonElement;
    expect(toggle).toBeTruthy();
    expect(toggle.textContent).toContain('enabled');

    toggle.click();
    await Promise.resolve(); // let the async click handler reach its first `await`
    const req = httpMock.expectOne('/api/admin/rules/t1-class-absent');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ auto_determination_enabled: false });
    req.flush({
      rule_id: 't1-class-absent',
      auto_determination_enabled: false,
      agreement_bar: 0.9,
      epss_hard_block_threshold: null,
      routing_difference_count: null,
      updated_by: 'admin1',
      updated_at: new Date().toISOString(),
    });
    await Promise.resolve();
    httpMock.expectOne('/api/admin/rules').flush(RULES);
    await settle(fixture);
  });

  it('an auto-suspended rule shows the reason', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/admin/rules').flush(RULES);
    await settle(fixture);
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('auto-suspended');
  });

  it('the three unregistered rules are clearly marked, separate from the registered table', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/admin/rules').flush(RULES);
    await settle(fixture);

    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('t1-cve-withdrawn');
    expect(text).toContain('t2-gadget-absent');
    expect(text).toContain('t2-runtime-immune');
    expect(text).toContain('UNREGISTERED');
    expect(text).toContain('no evidence source');

    // None of the three ever appear as a row in the registered rules table.
    const registeredRows = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('table.data-table tbody tr'));
    expect(registeredRows.some((r) => r.textContent?.includes('t1-cve-withdrawn'))).toBeFalse();
  });

  it(
    'the EPSS threshold "impact" only appears AFTER Save — there is no client-side preview — and the ' +
      'no-dry-run disclosure is always visible',
    async () => {
      const fixture = await create();
      httpMock.expectOne('/api/admin/rules').flush(RULES);
      await settle(fixture);

      expect((fixture.nativeElement as HTMLElement).textContent).toContain('No preview endpoint exists');
      expect(fixture.componentInstance['epssResult']()).toBeNull();

      fixture.componentInstance['epssDraft'].set('0.2');
      await settle(fixture);
      expect(fixture.componentInstance['epssCanSave']()).toBeTrue();

      const savePromise = fixture.componentInstance['saveEpssThreshold']();
      const req = httpMock.expectOne('/api/admin/rules/t3-epss');
      expect(req.request.body).toEqual({ epss_hard_block_threshold: 0.2 });
      req.flush({
        rule_id: 't3-epss',
        auto_determination_enabled: null,
        agreement_bar: null,
        epss_hard_block_threshold: 0.2,
        routing_difference_count: 7,
        updated_by: 'admin1',
        updated_at: new Date().toISOString(),
      });
      await Promise.resolve();
      httpMock.expectOne('/api/admin/rules').flush(RULES);
      await savePromise;
      await settle(fixture);

      expect(fixture.componentInstance['epssResult']()).toBe(7);
      expect((fixture.nativeElement as HTMLElement).textContent).toContain('7 of the last 30 days');
    },
  );

  it('Save is disabled until the EPSS draft actually differs from the current threshold', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/admin/rules').flush(RULES);
    await settle(fixture);
    expect(fixture.componentInstance['epssCanSave']()).toBeFalse();
  });

  it('per-rule "History" is disabled with an explanation — no version-history endpoint exists', async () => {
    const fixture = await create();
    httpMock.expectOne('/api/admin/rules').flush(RULES);
    await settle(fixture);

    const historyButtons = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('button')).filter((b) =>
      b.textContent?.includes('History'),
    );
    expect(historyButtons.length).toBeGreaterThan(0);
    expect(historyButtons.every((b) => (b as HTMLButtonElement).disabled)).toBeTrue();
  });
});
