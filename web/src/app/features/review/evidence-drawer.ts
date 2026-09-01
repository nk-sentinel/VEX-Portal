import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  HostListener,
  computed,
  effect,
  inject,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';
import { DatePipe, JsonPipe } from '@angular/common';
import { HttpErrorResponse } from '@angular/common/http';
import { FormsModule } from '@angular/forms';

import { ReviewApiService } from '../../core/api';
import type { Justification, ReviewFindingDetail, ReviewFindingRow } from '../../core/api/models';
import { AuthService } from '../../core/auth/auth.service';
import {
  JUSTIFICATION_LABELS,
  OUTCOME_META,
  degradedReason,
  isDegraded,
  justificationOptionsForTier,
  tierBadgeClass,
  tierLabel,
} from './review.model';

type Verdict = 'not_affected' | 'affected' | 'needs_review';
type LoadState = 'loading' | 'loaded' | 'error';
type SaveState = 'idle' | 'saving' | 'error';

/**
 * The Evidence Drawer — a right-hand overlay over screens 5, 6 and 8
 * (`docs/design/ui-spec.md`), never a modal. Owns its own fetch (keyed off
 * `findingId`), the determination form, and its own focus trap; the parent
 * (`review-queue.ts`) owns only *whether* it is open, *which* finding, and
 * returning focus to the row that opened it on close.
 *
 * **Sections render in the spec's fixed order**: identity (header) ->
 * recommendation -> rule trace -> escalation signals (structurally its own
 * block, `.signals`, never interleaved with the trace — see
 * `core/design/outcome.scss`'s own comment on this) -> determination
 * controls.
 *
 * **A committed (already-decided) finding renders its determination as
 * read-only audit facts, not a re-editable form — a deliberate departure
 * from `docs/design/ui-mockups.html`'s illustrative JS state machine**,
 * which lets a reviewer re-pick a radio on an already-cleared row. Calling
 * `POST .../decide` again on an already-`NOT_AFFECTED` finding would create
 * a *second* `IqDeterminationLink`/IQ suppression
 * (`app/services/determination.py::commit_reviewer_clear` is append-only,
 * never idempotent) — flagged in the task report. The determination
 * controls (radios/justification/note/Save) render only while
 * `outcome === 'needs_review'`; a decided finding shows
 * `ReviewFindingDetail.determination` (tier, justification, decided_by/at,
 * `iq_suppressed`) as plain facts instead.
 *
 * **Save routes to `decide()` or `recommend()` depending on capability**,
 * never a client-side choice of "which endpoint" beyond that: an approver
 * committing a terminal outcome (`not_affected`/`affected`) calls
 * `decide()`; anyone else with `recommend_determination` (including an
 * approver leaving the finding at `needs_review` with just a note) calls
 * `recommend()` — an audit entry only, per `app/api/review.py`'s module
 * docstring. `a`/`d` never auto-save (`review-queue.ts`'s keyboard handler
 * only sets the radio) — a stray keypress must never silently commit a
 * determination that touches Nexus IQ.
 */
@Component({
  selector: 'app-evidence-drawer',
  imports: [FormsModule, JsonPipe, DatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './evidence-drawer.html',
  // The host element itself carries no box — `.drawer` (the `<aside>` this
  // template renders) positions `absolute` against `ReviewQueue`'s own
  // `position: relative` page wrapper, exactly as if this component's host
  // were not in the tree at all. Without this, the default `display:
  // inline` host element sits between them and the drawer's positioning
  // context becomes whatever ancestor happens to be positioned instead.
  host: { style: 'display: contents' },
})
export class EvidenceDrawer {
  private readonly api = inject(ReviewApiService);
  private readonly auth = inject(AuthService);

  readonly findingId = input.required<string>();
  /** Screen 8 / a non-reviewer role (e.g. Auditor) — "Read-only in 8." */
  readonly readOnly = input(false);
  readonly hasPrev = input(false);
  readonly hasNext = input(false);

  readonly closed = output<void>();
  readonly prev = output<void>();
  readonly next = output<void>();
  /** Emitted after a successful save so the parent can patch its row cache without a full reload. */
  readonly rowUpdated = output<ReviewFindingRow>();

  private readonly drawerEl = viewChild.required<ElementRef<HTMLElement>>('drawerEl');

  protected readonly loadState = signal<LoadState>('loading');
  protected readonly detail = signal<ReviewFindingDetail | null>(null);
  protected readonly loadError = signal<string | null>(null);

  protected readonly verdict = signal<Verdict | null>(null);
  protected readonly justification = signal<Justification | ''>('');
  protected readonly secondConfirmer = signal('');
  protected readonly note = signal('');
  protected readonly saveState = signal<SaveState>('idle');
  protected readonly saveError = signal<string | null>(null);
  protected readonly savedMessage = signal<string | null>(null);

  protected readonly canCommit = computed(() => this.auth.hasCapability('commit_determination'));
  protected readonly canRecommend = computed(() => this.auth.hasCapability('recommend_determination'));
  protected readonly username = this.auth.username;

  protected readonly outcomeMeta = computed(() => {
    const d = this.detail();
    return d ? OUTCOME_META[d.outcome] : null;
  });
  protected readonly tierBadgeClass = computed(() => tierBadgeClass(this.detail()?.recommendation.tier ?? null));
  protected readonly tierLabel = computed(() => tierLabel(this.detail()?.recommendation.tier ?? null));

  protected readonly isHandoff = computed(() => this.detail()?.outcome === 'risk_acceptance_required');
  protected readonly isPending = computed(() => this.detail()?.outcome === 'needs_review');
  protected readonly canDetermine = computed(
    () => this.isPending() && !this.readOnly() && (this.canCommit() || this.canRecommend()),
  );

  protected readonly justificationOptions = computed(() =>
    justificationOptionsForTier(this.detail()?.recommendation.tier ?? null),
  );
  protected readonly noEvidenceToClear = computed(() => (this.detail()?.recommendation.tier ?? null) == null);

  protected readonly achievedTier = computed(() => this.detail()?.recommendation.tier ?? null);
  protected readonly needsSecondConfirmation = computed(
    () => this.verdict() === 'not_affected' && this.achievedTier() === 2,
  );

  /** Degraded (failed-collector) rows — see `review.model.ts`'s `isDegraded` docstring on why no live pipeline run sets this today. */
  protected readonly degradedEntries = computed(() =>
    (this.detail()?.rule_trace ?? []).filter((entry) => isDegraded(entry)),
  );
  protected readonly hasMissingEvidence = computed(() => (this.detail()?.missing_evidence?.length ?? 0) > 0);

  protected readonly canSave = computed(() => {
    if (this.saveState() === 'saving') return false;
    const v = this.verdict();
    if (v === 'not_affected') {
      if (!this.justification()) return false;
      if (this.needsSecondConfirmation() && this.canCommit()) {
        const confirmer = this.secondConfirmer().trim();
        if (!confirmer || confirmer === this.username()) return false;
      }
      return true;
    }
    if (v === 'affected') return true;
    if (v === 'needs_review') {
      // Nothing to commit; only worth saving as a note via `recommend()`.
      return this.note().trim().length > 0 && this.canRecommend();
    }
    return false;
  });

  protected readonly degradedReason = degradedReason;
  protected readonly isDegraded = isDegraded;
  protected readonly justificationLabel = (j: Justification): string => JUSTIFICATION_LABELS[j];
  protected readonly downloadPackageUrl = computed(() => `/api/risk-acceptance/${encodeURIComponent(this.findingId())}/package`);
  /** `VIEW_RISK_ACCEPTANCE` (risk_manager/auditor) — never reviewer/approver; see the task report. */
  protected readonly canDownloadPackage = computed(() => this.auth.hasCapability('view_risk_acceptance'));

  constructor() {
    effect(() => {
      const id = this.findingId();
      void this.load(id);
    });

    // Focus the close button whenever a *different* finding's detail
    // finishes loading (the drawer just opened, or `prev`/`next` swapped
    // the target) — "the drawer traps focus while open"; where it lands
    // its initial focus is part of that trap.
    effect(() => {
      if (this.loadState() === 'loaded') {
        queueMicrotask(() => this.focusFirst());
      }
    });
  }

  private async load(findingId: string): Promise<void> {
    this.loadState.set('loading');
    this.loadError.set(null);
    this.savedMessage.set(null);
    this.saveState.set('idle');
    try {
      const detail = await this.fetchDetail(findingId);
      this.detail.set(detail);
      this.verdict.set(detail.outcome === 'needs_review' ? null : (detail.outcome as Verdict));
      this.justification.set(detail.recommendation.justification ?? '');
      this.secondConfirmer.set('');
      this.note.set('');
      this.loadState.set('loaded');
    } catch (error) {
      this.loadError.set(EvidenceDrawer.messageFor(error));
      this.loadState.set('error');
    }
  }

  private fetchDetail(findingId: string): Promise<ReviewFindingDetail> {
    return new Promise((resolve, reject) => {
      this.api.getFinding(findingId).subscribe({ next: resolve, error: reject });
    });
  }

  /** Called both by this component's own template and by `ReviewQueue`'s keyboard handler (`a`/`d` set outcomes — never auto-save; see this class's docstring). */
  selectVerdict(v: Verdict): void {
    if (!this.canDetermine()) return;
    this.verdict.set(v);
    if (v !== 'not_affected') this.justification.set('');
  }

  protected async save(): Promise<void> {
    const d = this.detail();
    const v = this.verdict();
    if (!d || !v || !this.canSave()) return;

    this.saveState.set('saving');
    this.saveError.set(null);
    try {
      let row: ReviewFindingRow;
      if ((v === 'not_affected' || v === 'affected') && this.canCommit()) {
        row = await this.decide(d.id, v);
      } else {
        await this.recommend(d.id, v);
        // `recommend()` never mutates the finding — re-fetch so the drawer
        // (and the queue row it patches) reflect the real, unchanged state
        // rather than this component guessing at one.
        const refreshed = await this.fetchDetail(d.id);
        this.detail.set(refreshed);
        this.savedMessage.set('Recommendation recorded.');
        this.saveState.set('idle');
        return;
      }
      this.detail.set(await this.fetchDetail(d.id));
      this.savedMessage.set(`Determination saved for ${d.cve}.`);
      this.saveState.set('idle');
      this.rowUpdated.emit(row);
    } catch (error) {
      // "determination save failed: keep the reviewer's input, do not close the drawer."
      this.saveError.set(EvidenceDrawer.messageFor(error));
      this.saveState.set('error');
    }
  }

  private decide(findingId: string, outcome: 'not_affected' | 'affected'): Promise<ReviewFindingRow> {
    return new Promise((resolve, reject) => {
      this.api
        .decide(findingId, {
          outcome,
          justification: outcome === 'not_affected' ? (this.justification() as Justification) : null,
          note: this.note().trim() || null,
          second_confirmer: this.needsSecondConfirmation() ? this.secondConfirmer().trim() : null,
        })
        .subscribe({ next: resolve, error: reject });
    });
  }

  private recommend(findingId: string, outcome: Verdict): Promise<void> {
    return new Promise((resolve, reject) => {
      this.api
        .recommend(findingId, {
          outcome,
          justification: outcome === 'not_affected' ? (this.justification() as Justification) || null : null,
          note: this.note().trim() || null,
        })
        .subscribe({ next: () => resolve(), error: reject });
    });
  }

  private static messageFor(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (typeof error.error?.detail === 'string') return error.error.detail;
      if (error.status === 0) return 'The portal is unreachable. Your input has not been lost — try again.';
    }
    return 'That did not save. Your input has not been lost — try again.';
  }

  protected close(): void {
    this.closed.emit();
  }

  protected retryLoad(): void {
    void this.load(this.findingId());
  }

  // --- Focus trap -----------------------------------------------------
  //
  // "The drawer traps focus while open and returns focus to the
  // originating row on close" (ui-spec, Accessibility). Tab/Shift+Tab wrap
  // within the drawer's own focusable elements; the originating-row-focus
  // part is `review-queue.ts`'s responsibility (it owns the row elements),
  // triggered by this component's `closed` output.

  private focusable(): HTMLElement[] {
    const root = this.drawerEl().nativeElement;
    return Array.from(
      root.querySelectorAll<HTMLElement>(
        'button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])',
      ),
    );
  }

  private focusFirst(): void {
    this.focusable()[0]?.focus();
  }

  @HostListener('keydown', ['$event'])
  protected onKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      event.stopPropagation();
      this.close();
      return;
    }
    if (event.key !== 'Tab') return;
    const focusable = this.focusable();
    if (focusable.length === 0) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;
    if (event.shiftKey && active === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  }
}
