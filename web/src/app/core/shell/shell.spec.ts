import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';

import { Shell } from './shell';
import { AuthService } from '../auth/auth.service';
import { NAV_ITEMS } from './nav';

describe('Shell — nav visibility follows the session\'s roles (a courtesy; the server enforces regardless)', () => {
  let httpMock: HttpTestingController;
  let auth: AuthService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Shell],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }).compileComponents();
    httpMock = TestBed.inject(HttpTestingController);
    auth = TestBed.inject(AuthService);
  });

  afterEach(() => httpMock.verify());

  async function signInAs(...roles: string[]): Promise<void> {
    const p = auth.bootstrap();
    httpMock.expectOne('/api/auth/me').flush({ username: 'test-user', roles });
    await p;
  }

  it('a reviewer sees only Review Queue, nothing requester/admin/risk-manager only', async () => {
    await signInAs('reviewer');
    const fixture = TestBed.createComponent(Shell);
    fixture.detectChanges();

    const labels = fixture.componentInstance['visibleNavItems']().map((i: { label: string }) => i.label);
    expect(labels).toEqual(['Review Queue']);
  });

  it('a requester sees New Assessment and My Assessments only', async () => {
    await signInAs('requester');
    const fixture = TestBed.createComponent(Shell);
    fixture.detectChanges();

    const labels = fixture.componentInstance['visibleNavItems']().map((i: { label: string }) => i.label);
    expect(labels).toEqual(['New Assessment', 'My Assessments']);
  });

  it('an auditor sees Review Queue, Dashboard and Risk Acceptance (read-only oversight roles), never Rules & Thresholds', async () => {
    await signInAs('auditor');
    const fixture = TestBed.createComponent(Shell);
    fixture.detectChanges();

    const labels = fixture.componentInstance['visibleNavItems']().map((i: { label: string }) => i.label);
    expect(labels).toEqual(['Review Queue', 'Dashboard', 'Risk Acceptance']);
  });

  it('an admin sees Dashboard (VIEW_DASHBOARD is auditor+admin) and Rules & Thresholds, nothing requester/reviewer-only', async () => {
    await signInAs('admin');
    const fixture = TestBed.createComponent(Shell);
    fixture.detectChanges();

    const labels = fixture.componentInstance['visibleNavItems']().map((i: { label: string }) => i.label);
    expect(labels).toEqual(['Dashboard', 'Rules & Thresholds']);
  });

  it('a session with no roles sees an empty rail, not every item (fail closed, not fail open)', async () => {
    await signInAs();
    const fixture = TestBed.createComponent(Shell);
    fixture.detectChanges();

    expect(fixture.componentInstance['visibleNavItems']()).toEqual([]);
  });

  it('every NAV_ITEMS route renders as a link only when its capability is held — rendered DOM matches the model', async () => {
    await signInAs('reviewer');
    const fixture = TestBed.createComponent(Shell);
    fixture.detectChanges();

    const hrefs = Array.from(fixture.nativeElement.querySelectorAll('.sidebar .nav a.nav-item')).map(
      (a) => (a as HTMLAnchorElement).getAttribute('href'),
    );
    expect(hrefs).toEqual(['/review']);
    // Sanity: this really did filter something out, not just happen to match.
    expect(NAV_ITEMS.length).toBeGreaterThan(1);
  });

  it('the persona indicator shows the username and every role held, not just the landing-page role', async () => {
    await signInAs('reviewer', 'approver');
    const fixture = TestBed.createComponent(Shell);
    fixture.detectChanges();

    const text = (fixture.nativeElement as HTMLElement).querySelector('.persona')?.textContent ?? '';
    expect(text).toContain('test-user');
    expect(text).toContain('Reviewer');
    expect(text).toContain('Approver');
  });
});
