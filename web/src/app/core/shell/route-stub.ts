import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { map } from 'rxjs';

/**
 * Placeholder for a screen not yet built (Tasks 3–5:
 * `docs/plans/2026-09-01-screens.md`). Every routed screen in this task
 * (New Assessment, My Assessments, Review Queue, Dashboard, Risk
 * Acceptance, Rules & Thresholds) resolves here today so the shell's
 * navigation and route guards — this task's actual scope — can be
 * exercised against the real route table rather than an empty one.
 *
 * Takes its heading from route `data.title` so one component serves every
 * placeholder route without a copy-pasted component per screen.
 */
@Component({
  selector: 'app-route-stub',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="page">
      <div class="page__head">
        <div>
          <p class="eyebrow">Not built yet</p>
          <h1>{{ title() }}</h1>
          <p class="sub">This screen is scoped to a later task and is not implemented here.</p>
        </div>
      </div>
    </div>
  `,
})
export class RouteStub {
  private readonly route = inject(ActivatedRoute);

  protected readonly title = toSignal(
    this.route.data.pipe(map((data) => (data['title'] as string | undefined) ?? 'Coming soon')),
    { initialValue: 'Coming soon' },
  );
}
