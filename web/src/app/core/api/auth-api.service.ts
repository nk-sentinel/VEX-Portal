import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import type { Observable } from 'rxjs';

import type { IdentityResponse, LoginRequest } from './models';

/**
 * `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`.
 *
 * Every call is same-origin (this app is always served from the same
 * origin as `/api`, either through the dev-server proxy — `proxy.conf.json`
 * — or, in production, behind the same Traefik host), so the browser sends
 * the session cookie automatically; there is no `withCredentials` to set
 * here, unlike a cross-origin deployment.
 *
 * The session cookie is `httpOnly` (`app/middleware/session.py`) — this
 * client can never read it directly, only ask the server who it thinks is
 * signed in via `me()`. That is deliberate: the roles a screen renders come
 * from the server's answer, never from anything decoded client-side, and
 * every action endpoint re-checks the caller's capability independently
 * regardless of what this client believes (rule 3 — the UI is never the
 * enforcement point).
 */
@Injectable({ providedIn: 'root' })
export class AuthApiService {
  private readonly http = inject(HttpClient);

  login(body: LoginRequest): Observable<IdentityResponse> {
    return this.http.post<IdentityResponse>('/api/auth/login', body);
  }

  logout(): Observable<Record<string, string>> {
    return this.http.post<Record<string, string>>('/api/auth/logout', {});
  }

  me(): Observable<IdentityResponse> {
    return this.http.get<IdentityResponse>('/api/auth/me');
  }
}
