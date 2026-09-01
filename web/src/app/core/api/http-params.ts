import { HttpParams } from '@angular/common/http';

/**
 * Builds `HttpParams` from a plain query object, skipping `undefined`/`null`
 * entries entirely (never sending `?foo=undefined`) and appending an array
 * value as repeated keys (`?state=a&state=b`) — the form FastAPI/Starlette
 * expects for a `list[str] | None` query parameter such as
 * `GET /api/review/findings`'s `state`.
 */
export function toHttpParams<T extends object>(query: T | undefined): HttpParams {
  let params = new HttpParams();
  if (!query) return params;
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item === undefined || item === null) continue;
        params = params.append(key, String(item));
      }
    } else {
      params = params.set(key, String(value));
    }
  }
  return params;
}
