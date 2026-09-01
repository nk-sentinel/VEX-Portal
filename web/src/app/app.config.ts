import { type ApplicationConfig, inject, provideAppInitializer, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { provideRouter } from '@angular/router';

import { routes } from './app.routes';
import { AuthService } from './core/auth/auth.service';
import { sessionExpiredInterceptor } from './core/auth/session-expired.interceptor';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes),
    provideHttpClient(withInterceptors([sessionExpiredInterceptor])),
    // Resolves the session from `GET /api/auth/me` before the router's
    // first navigation, so `authGuard`'s first evaluation already has a
    // real answer instead of racing it — see `AuthService.bootstrap()`'s
    // docstring on the triple-state `identity()` signal this depends on.
    provideAppInitializer(() => inject(AuthService).bootstrap()),
  ],
};
