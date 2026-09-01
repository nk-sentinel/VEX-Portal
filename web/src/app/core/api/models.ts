/**
 * Typed models for the VEX Portal API — hand-written against the live
 * OpenAPI document at `GET /openapi.json` (22 routes under `/api`, one
 * `/health`; 42 component schemas), not code-generated.
 *
 * Why hand-written rather than `@openapitools/openapi-generator-cli`
 * (DAST-Portal's choice, `web/openapitools.json`): that generator needs a
 * Java runtime and emits a few hundred files (services, a runtime module,
 * an index) for what is, here, 22 endpoints — the generator itself would be
 * the only "npm dependency beyond what `ng new` and the API client need"
 * this task would otherwise add. A hand-written client needs nothing beyond
 * `@angular/common/http`, already part of `ng new`'s output, and every
 * shape below is checked against the live server by
 * `scripts/verify-api-client.mjs` (see that file and `README` in this
 * folder) — so drift from the real API is still caught, just not by
 * codegen.
 *
 * Every interface and string-union below is transcribed field-for-field
 * from `components.schemas` in the live document, keeping the same
 * nullability: an OpenAPI `anyOf: [T, {type: null}]` becomes `T | null`
 * here, never silently narrowed to `T`. Docstrings quote the schema's own
 * `description` where one exists, because several of them carry rulings
 * ("never a route around `commit_determination`") that matter to a caller.
 */

// ---------------------------------------------------------------------------
// Enums (OpenAPI string/int enums -> TS unions, matching the wire values).
// ---------------------------------------------------------------------------

/** Where an assessment sits in its review lifecycle. */
export type AssessmentState =
  | 'draft'
  | 'admission'
  | 'admission_failed'
  | 'analysing'
  | 'needs_review'
  | 'awaiting_approval'
  | 'completed'
  | 'expired';

/**
 * Where one finding landed, at the finding-record's granularity.
 *
 * Deliberately not the same set as {@link State}: a finding can also be
 * `needs_review` (routed to a human, nothing decided yet) or
 * `risk_acceptance_required` (no fix available — never a `not_affected`
 * determination). Never render `risk_acceptance_required` as a determination
 * — see `docs/design/ui-spec.md`'s "Risk Acceptance Required is not a
 * determination and must not be styled as one."
 */
export type FindingOutcome = 'not_affected' | 'affected' | 'needs_review' | 'risk_acceptance_required';

/** The VEX analysis state of a determination (CycloneDX VEX, used verbatim). */
export type State = 'not_affected' | 'affected' | 'in_triage';

/**
 * Why a `not_affected` determination holds. The CycloneDX VEX
 * justifications; only a subset is ever permitted at a given evidence tier
 * — the server enforces which, this client never decides that itself
 * (rule 3: the UI is never the enforcement point).
 */
export type Justification =
  | 'code_not_present'
  | 'code_not_reachable'
  | 'requires_dependency'
  | 'requires_configuration'
  | 'requires_environment'
  | 'protected_at_perimeter'
  | 'protected_by_mitigating_control';

/** The strength of the evidence behind a signal. */
export type EvidenceTier = 1 | 2 | 3;

/** The adjudicator's self-reported certainty. */
export type Confidence = 'high' | 'medium' | 'low' | 'insufficient_evidence';

export type SlaBand = 'breaching' | 'urgent' | 'ok' | 'n/a';

/** Manually set by the risk manager. The portal only records this. */
export type HandoffStatus = 'awaiting_hand_off' | 'with_risk_manager' | 'accepted' | 'rejected';

/** Which of the three admission checks. */
export type AdmissionCheckKind = 'report' | 'artifact' | 'provenance';

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export interface LoginRequest {
  username: string;
  password: string;
}

/**
 * The caller's identity and roles, as the server believes them — never
 * anything the client supplied. Returned by both `POST /api/auth/login`
 * and `GET /api/auth/me`.
 */
export interface IdentityResponse {
  username: string;
  roles: string[];
}

// ---------------------------------------------------------------------------
// Assessments (screens 2, 3, 4)
// ---------------------------------------------------------------------------

export interface ApplicationOut {
  id: string;
  name: string;
}

/** Which admission check failed, and what to do about it. */
export interface AdmissionFailureOut {
  check: AdmissionCheckKind;
  message: string;
}

export interface OutcomeCounts {
  not_affected: number;
  affected: number;
  needs_review: number;
  risk_acceptance_required: number;
}

/**
 * One finding at the detail a requester (screen 4) needs: outcome and the
 * reason in plain language — never the reviewer's full rule trace /
 * escalation-signal breakdown (that is {@link ReviewFindingDetail}, scoped
 * to reviewers/approvers).
 */
export interface FindingOut {
  id: string;
  cve: string;
  purl: string;
  outcome: FindingOutcome | null;
  reason: string;
  tier: EvidenceTier | null;
  justification: Justification | null;
  confidence: Confidence | null;
  evidence_refs: string[];
  decided_at: string | null;
}

/** One row on [3] My Assessments — assessment-level, not finding-level. */
export interface AssessmentSummary {
  id: string;
  application_id: string;
  report_id: string;
  state: AssessmentState;
  requester: string;
  requester_note: string | null;
  finding_count: number;
  outcome_counts: OutcomeCounts;
  created_at: string;
  submitted_at: string | null;
  expires_at: string | null;
  admission_failure: AdmissionFailureOut | null;
}

/** [4] Assessment Result: the assessment header plus every finding. */
export interface AssessmentDetail {
  id: string;
  application_id: string;
  report_id: string;
  state: AssessmentState;
  requester: string;
  requester_note: string | null;
  commit_sha: string | null;
  artifact_ref: string | null;
  created_at: string;
  submitted_at: string | null;
  expires_at: string | null;
  admission_failure: AdmissionFailureOut | null;
  /** Arbitrary provenance-check payload — shape not pinned by the schema. */
  provenance: Record<string, unknown> | null;
  outcome_counts: OutcomeCounts;
  findings: FindingOut[];
}

/** [2] New Assessment's submit body. */
export interface RaiseAssessmentRequest {
  application_id: string;
  report_id: string;
  artifact_coordinates: string;
  commit_sha?: string | null;
  requester_note: string;
}

// ---------------------------------------------------------------------------
// Review (screens 5, 6, the Evidence Drawer)
// ---------------------------------------------------------------------------

/** One row in the queue table — [5] Review Queue's columns. */
export interface ReviewFindingRow {
  id: string;
  assessment_id: string;
  application_id: string;
  cve: string;
  purl: string;
  outcome: FindingOutcome;
  recommended_outcome: FindingOutcome;
  tier: EvidenceTier | null;
  justification: Justification | null;
  confidence: Confidence | null;
  sla_band: SlaBand;
  sla_hours_remaining: number | null;
  age_hours: number;
  requester: string;
  decided_by: string | null;
  decided_at: string | null;
}

/**
 * CVSS, EPSS, KEV and fix availability for one finding's CVE.
 *
 * Structurally separate from the rule trace and the recommendation on
 * purpose — never render this adjacent to a Not Affected verdict in a way
 * that reads as supporting it (`docs/design/ui-spec.md` section 0). Every
 * field is optional/nullable because each is itself a tri-state "not looked
 * up" fact: `null` means unknown, never a coerced safe default.
 */
export interface EscalationSignals {
  epss?: number | null;
  kev?: boolean | null;
  cvss_base_score?: number | null;
  cvss_vector?: string | null;
  fix_available?: boolean | null;
  hard_blockers?: string[];
  /** Always "not a basis for clearing" — render it, don't hardcode it. */
  note?: string;
}

/** One Tier 1/2 rule's result — the audit surface and reviewer's trust surface. */
export interface RuleTraceEntry {
  rule_id: string;
  rule_version: string;
  tier: EvidenceTier;
  verdict: string;
  detail: Record<string, unknown>;
}

/** The Evidence Drawer's "RECOMMENDATION" section — never a bare enum. */
export interface RecommendationOut {
  outcome: FindingOutcome;
  reason: string;
  tier: EvidenceTier | null;
  justification: Justification | null;
  confidence: Confidence | null;
  requires_second_confirmation: boolean;
}

/** One AI adjudicator pass, as the reviewer needs to see it. */
export interface AiVerdictOut {
  model_id: string;
  prompt_version: string;
  state: State;
  justification: Justification | null;
  confidence: Confidence;
  evidence_refs: string[];
  missing_evidence: string[];
  refuted_by: string | null;
}

/** The committed determination, when this finding already has one. */
export interface DeterminationOut {
  tier: EvidenceTier;
  justification: Justification;
  confidence: Confidence;
  evidence_refs: string[];
  decided_by: string;
  decided_at: string;
  iq_suppressed: boolean;
}

/** The Evidence Drawer's full payload for one finding. */
export interface ReviewFindingDetail {
  id: string;
  assessment_id: string;
  application_id: string;
  cve: string;
  purl: string;
  threat_level: number | null;
  outcome: FindingOutcome;
  recommendation: RecommendationOut;
  rule_trace: RuleTraceEntry[];
  escalation: EscalationSignals;
  ai_verdict: AiVerdictOut | null;
  missing_evidence?: string[];
  determination?: DeterminationOut | null;
}

/**
 * A reviewer's non-binding proposal — recorded as an audit entry only,
 * never a route around the approver's commit action.
 */
export interface RecommendRequest {
  outcome: 'not_affected' | 'affected' | 'needs_review';
  justification?: Justification | null;
  note?: string | null;
}

export interface RecommendationRecorded {
  finding_id: string;
  outcome: string;
  recorded_by: string;
  recorded_at: string;
}

/**
 * An approver's commit action. No `tier` field: the achieved tier is
 * derived server-side from the finding's own rule trace / AI verdict, never
 * asserted by the caller. `second_confirmer` is required whenever the
 * derived tier is Tier 2 (STRONG) — the server refuses the commit
 * otherwise; this client does not pre-validate that, it only carries the
 * field.
 */
export interface DecideRequest {
  outcome: 'not_affected' | 'affected';
  justification?: Justification | null;
  note?: string | null;
  second_confirmer?: string | null;
}

// ---------------------------------------------------------------------------
// Risk acceptance (screen 8)
// ---------------------------------------------------------------------------

/**
 * A row in the Risk Acceptance Queue. Only `RISK_ACCEPTANCE_REQUIRED`
 * findings ever appear here — never render this table's rows as
 * determinations; the IQ violation is still open for every one of them.
 */
export interface RiskAcceptanceRow {
  finding_id: string;
  assessment_id: string;
  application_id: string;
  cve: string;
  purl: string;
  reason: string;
  escalation: EscalationSignals;
  affected_applications_count: number;
  age_hours: number;
  status: HandoffStatus;
  status_updated_by: string | null;
  status_updated_at: string | null;
}

/** Manually set by the risk manager; the portal never enforces this. */
export interface HandoffStatusUpdate {
  status: HandoffStatus;
}

// ---------------------------------------------------------------------------
// Admin (screen 9)
// ---------------------------------------------------------------------------

/** A Tier 1 or Tier 2 rule — the only rules that may ever auto-clear a finding. */
export interface ToggleableRuleOut {
  rule_id: string;
  tier: EvidenceTier;
  version: string;
  has_auto_determination_toggle: true;
  auto_determination_enabled: boolean;
  agreement_bar: number | null;
  agreement_rate: number | null;
  auto_suspended: boolean;
  volume_30d: number;
  thresholds?: Record<string, number>;
}

/**
 * A Tier 3 (ESCALATION) rule. Never carries `auto_determination_enabled` —
 * render NO toggle for these, not a disabled one
 * (`docs/design/ui-spec.md`: "Not disabled — absent, because the capability
 * does not exist. Rendering a greyed-out toggle implies it could be turned
 * on.").
 */
export interface EscalationRuleOut {
  rule_id: string;
  tier: EvidenceTier;
  version: string;
  has_auto_determination_toggle: false;
  volume_30d: number;
  thresholds?: Record<string, number>;
}

/**
 * A rule id deliberately unregistered because its evidence source does not
 * exist yet.
 */
export interface PendingRuleOut {
  rule_id: string;
  registered: false;
  reason: string;
}

export type RuleOut = ToggleableRuleOut | EscalationRuleOut | PendingRuleOut;

/**
 * A change to one rule's configuration. Every field is optional — only the
 * fields supplied are changed. `auto_determination_enabled` is refused
 * (422) server-side for a Tier 3 rule id or an unknown one.
 */
export interface RuleUpdateRequest {
  auto_determination_enabled?: boolean | null;
  agreement_bar?: number | null;
  epss_hard_block_threshold?: number | null;
}

export interface RuleUpdateResult {
  rule_id: string;
  auto_determination_enabled: boolean | null;
  agreement_bar: number | null;
  epss_hard_block_threshold: number | null;
  /** How many of the last 30 days' findings would route differently. */
  routing_difference_count: number | null;
  updated_by: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Dashboard (screen 7)
// ---------------------------------------------------------------------------

export interface VolumePanel {
  since: string;
  until: string;
  total_assessments: number;
  total_findings: number;
  findings_by_outcome?: Record<string, number>;
}

/** "The headline number for whether the portal is working" — ui-spec. */
export interface AutomationSplitPanel {
  since: string;
  until: string;
  total_decided: number;
  automated: number;
  human_reviewed: number;
  automated_ratio: number | null;
}

export interface SlaPanel {
  since: string;
  until: string;
  median_hours_to_determination: number | null;
  p90_hours_to_determination: number | null;
  sample_size: number;
  breaching_count: number;
}

export interface RuleAgreementOut {
  rule_id: string;
  tier: EvidenceTier;
  agreement_rate: number | null;
  agreement_bar: number | null;
  below_bar: boolean;
  volume_30d: number;
}

/** "The trust metric" — per-rule, not scoped by application. */
export interface AgreementPanel {
  since: string;
  until: string;
  rules?: RuleAgreementOut[];
}

export interface OutcomeMixRow {
  application_id: string;
  not_affected: number;
  affected: number;
  risk_acceptance_required: number;
}

export interface OutcomeMixPanel {
  since: string;
  until: string;
  by_application?: OutcomeMixRow[];
}

/** "Incoming reassessment load" — ui-spec. */
export interface ExpiryPanel {
  lapsing_within_7_days: number;
  already_expired: number;
}

// ---------------------------------------------------------------------------
// Query parameter shapes (not schemas — request parameters).
// ---------------------------------------------------------------------------

export interface ReviewFindingsQuery {
  state?: string[];
  application_id?: string;
  assessment_id?: string;
  tier?: string;
  sla?: SlaBand;
  search?: string;
}

export interface DashboardRangeQuery {
  application_id?: string;
  since?: string;
  until?: string;
}
