# Naming

## What VEX stands for

**VEX — Vulnerability Exploitability eXchange.**

An open standard for recording whether a known vulnerability *actually affects* a specific
product. An SBOM tells you a component is present; VEX tells you whether the vulnerability in
that component is exploitable in your context.

It exists because software composition analysis tools generate large volumes of findings that
do not apply, and before VEX there was no standard way to say so — every organisation invented
its own vocabulary for "we looked at this and it doesn't affect us", which made those
statements impossible to exchange, audit, or automate against.

A VEX statement carries a **state**, and where the state is *not affected*, a **justification**:

| VEX state | What it means |
|---|---|
| `not_affected` | The vulnerability is not exploitable in this product |
| `affected` | It is exploitable; remediation is required |
| `in_triage` | Under investigation; not yet determined |

Justifications available for `not_affected`:

`code_not_present` · `code_not_reachable` · `requires_dependency` ·
`requires_configuration` · `requires_environment` · `protected_at_perimeter` ·
`protected_by_mitigating_control`

Two implementations are in common use: **CycloneDX VEX** and **CSAF VEX** (OASIS). This portal
uses CycloneDX, because that is what Sonatype IQ speaks — its VEX endpoint accepts exactly
these fields.

## Why the portal is called VEX Portal

**The name describes the output rather than decorating it.** The portal's determination states
and justifications are not an invented vocabulary — they are the CycloneDX VEX enums, used
verbatim. Naming it after the standard it implements makes that literal rather than
aspirational.

Three further reasons:

**It is defensible to an auditor.** "We recorded this determination in CycloneDX VEX format" is
a materially stronger sentence than "we categorised it using our internal scheme". The standard
does the work of justifying the category.

**It carries no implication of suppression.** This constraint drove the whole naming exercise —
see below.

**It matches the existing naming pattern.** DAST Portal, VEX Portal. Four letters and three,
both acronyms that are accurate rather than clever, both saying what the tool is for without
requiring a story.

Accepted trade-off: VEX is well known to AppSec and supply-chain practitioners, and
increasingly to auditors — SBOM and VEX appear in regulatory language such as US Executive
Order 14028 and the EU Cyber Resilience Act — but it is not widely known outside that circle.
Where the audience is unfamiliar, "Exploitability Portal" was the alternative considered, and
it explains itself at the cost of being longer and less precise.

The vendor name was deliberately dropped. Tying an internal tool's identity to NexusIQ would
make it awkward if Sonatype is ever replaced; the portal's concepts survive a change of
scanner, so its name should too.

## The constraint that shaped everything: never say "waiver"

Nexus IQ calls the underlying mechanism a *waiver*. This portal does not, anywhere a person can
see it.

The word reads to audit and management as **suppressing a real finding** — as though the
vulnerability is present and being excused. That is not what the portal does. It determines
whether the vulnerability applies at all, on evidence. Those are different claims with
different risk implications, and using the same word for both loses the distinction precisely
where it matters most.

So the portal records **determinations**. The IQ waiver is the *enforcement mechanism* behind a
`not_affected` determination — an implementation detail confined to the IQ adapter, never
surfaced in the UI, notifications, exports, or API field names.

| Use | Never use |
|---|---|
| Exploitability Assessment | waiver request |
| Determination | waiver, exception |
| Not Affected | waived, suppressed, accepted |
| Affected | vulnerable, failed |
| Under Investigation | pending, unknown |
| Reassessment | renewal, extension |

This is not cosmetic. A finding with no fix available never receives a determination at all —
it is marked `RISK_ACCEPTANCE_REQUIRED` and leaves the portal's flow entirely, with the IQ
violation left open. Calling that a "waiver" would make accepted risk look resolved, which is
the specific failure the vocabulary exists to prevent.

## Names considered and rejected

| Name | Why not |
|---|---|
| **Vantage** | Collides with NTT/WhiteHat *Vantage Inspect*, which determines OSS vulnerability exploitability — same space, same job |
| **Assay**, **Docket**, **Warrant**, **Touchstone** | Good names, all evidence- or determination-flavoured. Rejected for being evocative rather than descriptive: the surrounding tooling is named plainly, and a tool nobody can guess the purpose of from its name costs a sentence of explanation forever |
| Anything built on *Waive*, *Exempt*, *Clear*, *Pass*, *Bypass*, *Suppress* | Dead on arrival with audit, for the reasons above |
| Anything containing *IQ* | Sonatype's brand, not ours |
