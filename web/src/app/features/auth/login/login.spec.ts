import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ActivatedRoute, Router, convertToParamMap, provideRouter } from '@angular/router';

import { Login } from './login';

describe('Login', () => {
  let httpMock: HttpTestingController;
  let router: Router;

  function setUp(queryParams: Record<string, string> = {}) {
    TestBed.configureTestingModule({
      imports: [Login],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: ActivatedRoute,
          useValue: { snapshot: { queryParamMap: convertToParamMap(queryParams) } },
        },
      ],
    });
    httpMock = TestBed.inject(HttpTestingController);
    router = TestBed.inject(Router);
    spyOn(router, 'navigateByUrl').and.resolveTo(true);
    const fixture = TestBed.createComponent(Login);
    fixture.detectChanges();
    return fixture;
  }

  afterEach(() => httpMock.verify());

  it('default state: renders the form, submit disabled by nothing but validity (no error shown yet)', () => {
    const fixture = setUp();
    const html = (fixture.nativeElement as HTMLElement).innerHTML;
    expect(html).toContain('Username');
    expect(html).toContain('Password');
    expect(fixture.componentInstance['credentialError']()).toBeNull();
  });

  it('loading state: while a submission is in flight, the button reads "Signing in…" and the form disables', () => {
    const fixture = setUp();
    const el = fixture.nativeElement as HTMLElement;
    fixture.componentInstance['form'].setValue({ username: 'reviewer1', password: 'x' });

    (el.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'));
    fixture.detectChanges();

    expect(fixture.componentInstance['submitting']()).toBeTrue();
    expect(el.querySelector('button[type="submit"]')?.textContent).toContain('Signing in');
    expect((el.querySelector('input[formcontrolname="username"]') as HTMLInputElement).disabled).toBeTrue();

    httpMock.expectOne('/api/auth/login').flush({ detail: 'invalid username or password' }, { status: 401, statusText: 'Unauthorized' });
  });

  it(
    'error state: an unknown username and a known username with the wrong password render the IDENTICAL server ' +
      'message — the component never re-words or branches on which case it was, so it cannot leak which one happened',
    async () => {
      const fixture = setUp();

      fixture.componentInstance['form'].setValue({ username: 'no-such-user', password: 'x' });
      const firstSubmit = fixture.componentInstance['submit']();
      httpMock
        .expectOne('/api/auth/login')
        .flush({ detail: 'invalid username or password' }, { status: 401, statusText: 'Unauthorized' });
      await firstSubmit;
      const unknownUsernameMessage = fixture.componentInstance['credentialError']();

      fixture.componentInstance['form'].setValue({ username: 'reviewer1', password: 'wrong' });
      const secondSubmit = fixture.componentInstance['submit']();
      httpMock
        .expectOne('/api/auth/login')
        .flush({ detail: 'invalid username or password' }, { status: 401, statusText: 'Unauthorized' });
      await secondSubmit;
      const wrongPasswordMessage = fixture.componentInstance['credentialError']();

      expect(unknownUsernameMessage).toBe('invalid username or password');
      expect(wrongPasswordMessage).toBe('invalid username or password');
      expect(unknownUsernameMessage).toBe(wrongPasswordMessage);
    },
  );

  it('error state: renders the server\'s message verbatim, not a client-invented one', async () => {
    const fixture = setUp();
    fixture.componentInstance['form'].setValue({ username: 'reviewer1', password: 'wrong' });
    const submitPromise = fixture.componentInstance['submit']();
    httpMock
      .expectOne('/api/auth/login')
      .flush({ detail: 'a distinctive server-provided message' }, { status: 401, statusText: 'Unauthorized' });
    await submitPromise;
    fixture.detectChanges();

    expect(fixture.componentInstance['credentialError']()).toBe('a distinctive server-provided message');
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('a distinctive server-provided message');
  });

  it('error state: a downed auth directory (503) shows a distinct message from a rejected credential (401)', async () => {
    const fixture = setUp();
    fixture.componentInstance['form'].setValue({ username: 'reviewer1', password: 'x' });
    const submitPromise = fixture.componentInstance['submit']();
    httpMock
      .expectOne('/api/auth/login')
      .flush({ detail: 'authentication service unavailable' }, { status: 503, statusText: 'Service Unavailable' });
    await submitPromise;

    expect(fixture.componentInstance['credentialError']()).toBe('authentication service unavailable');
  });

  it('a successful login with roles navigates to the role landing route (no returnUrl given)', async () => {
    const fixture = setUp();
    fixture.componentInstance['form'].setValue({ username: 'reviewer1', password: 'correct' });
    const submitPromise = fixture.componentInstance['submit']();
    httpMock.expectOne('/api/auth/login').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await submitPromise;

    expect(router.navigateByUrl).toHaveBeenCalledWith('/review');
  });

  it('a successful login honours a safe returnUrl over the default landing route', async () => {
    const fixture = setUp({ returnUrl: '/review/finding-42' });
    fixture.componentInstance['form'].setValue({ username: 'reviewer1', password: 'correct' });
    const submitPromise = fixture.componentInstance['submit']();
    httpMock.expectOne('/api/auth/login').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await submitPromise;

    expect(router.navigateByUrl).toHaveBeenCalledWith('/review/finding-42');
  });

  it('rejects an open-redirect returnUrl (protocol-relative //) and falls back to the landing route', async () => {
    const fixture = setUp({ returnUrl: '//evil.example.com/phish' });
    fixture.componentInstance['form'].setValue({ username: 'reviewer1', password: 'correct' });
    const submitPromise = fixture.componentInstance['submit']();
    httpMock.expectOne('/api/auth/login').flush({ username: 'reviewer1', roles: ['reviewer'] });
    await submitPromise;

    expect(router.navigateByUrl).toHaveBeenCalledWith('/review');
  });

  it(
    'a successful login with NO recognised role shows who is signed in and which groups grant access — ' +
      'never "access denied" — and does not navigate into the shell',
    async () => {
      const fixture = setUp();
      fixture.componentInstance['form'].setValue({ username: 'norole-user', password: 'correct' });
      const submitPromise = fixture.componentInstance['submit']();
      httpMock.expectOne('/api/auth/login').flush({ username: 'norole-user', roles: [] });
      await submitPromise;
      fixture.detectChanges();

      expect(router.navigateByUrl).not.toHaveBeenCalled();
      const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
      expect(text).toContain('norole-user');
      expect(text.toLowerCase()).not.toContain('access denied');
      // Names at least one real, contactable next step and at least one
      // actual role name a group could grant.
      expect(text).toContain('Requester');
      expect(text.toLowerCase()).toContain('contact');
    },
  );
});
