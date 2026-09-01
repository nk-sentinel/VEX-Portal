# fakes/ — THROWAWAY scaffolding. Not part of the product.

**This directory ships nowhere.** It exists only because this portal is being built on
shadowlab, a machine that cannot reach Nexus IQ, JFrog Artifactory, Bitbucket Data Center, or
AWS Bedrock. These four small FastAPI servers stand in for those systems so the **real**
adapter clients (`backend/app/adapters/{iq,jfrog,bitbucket,llm}/client.py`, built in Task 8) can
be exercised over real HTTP here, and plugging in the real systems at work becomes a URL change
(`ADAPTER_MODE=real` + the real `*_BASE_URL`s in `.env`) instead of a discovery exercise.

If you are reading this in six months wondering whether `fakes/` is something the portal
depends on: **it is not.**

- Nothing under `backend/app/` imports anything under `fakes/`, and nothing here should ever
  be made importable from there. `app.adapters.factory` (Task 8) chooses between the real
  client and a URL pointed at one of these processes — never between two Python
  implementations.
- These containers never run in the work network. `compose.yaml`'s `vex-fake-*` services are
  local-only scaffolding for `ADAPTER_MODE=fake` (the default — see `app/config.py`).
- Nothing here is validated, authenticated, rate-limited, or persisted beyond one process's
  lifetime. Waiver state created via the fake IQ server, for example, lives in a plain
  in-memory dict and is gone on restart.
- **Do not add features here.** If a real client needs a new fake route to be testable, add
  the smallest possible canned response for it — don't grow this into a second implementation
  of any of these four vendors.

## What's here

| Path | Serves |
|---|---|
| `iq/main.py` | Fake Nexus IQ Lifecycle (`/api/v2/applications`, report raw/policy, vulnerability lookup, remediation, source control, policy waivers, waiver reasons) |
| `jfrog/main.py` | Fake JFrog Artifactory (generic artifact download, `/api/build/{name}/{number}`) |
| `bitbucket/main.py` | Fake Bitbucket Data Center (raw file fetch, code search) |
| `bedrock/main.py` | Fake AWS Bedrock Runtime `InvokeModel` for a Claude model |
| `_shared.py` | Loads `data/*.json` and the sample artifact — shared by all four `main.py` files |
| `data/*.json`, `data/sample-artifact.jar` | The one canned scenario all four fakes serve (see below) |
| `tests/test_fakes.py` | Route tests + a real-subprocess-over-real-HTTP smoke test per fake — **not** part of `backend`'s pytest suite; see that file's docstring for how to run it |
| `Dockerfile` | One shared image; which fake a container runs is chosen by `command:` in `compose.yaml` |

## Vocabulary note

`fakes/iq/` is the one place in this entire repository allowed to say **"waiver"**. Nexus IQ's
own API is built on `policyWaivers` and `waiverReasonId` — see
`help.sonatype.com/iqserver/automating/rest-apis/policy-waiver-rest-api---v2`. Renaming those
fields to the portal's own vocabulary (`docs/naming.md`) would make this fake unfaithful to the
API it stands in for, which defeats the entire point of having it. Everywhere else in the
codebase (including `fakes/README.md` itself, above this section) the rule holds as normal.

## The one sample scenario

Every fake describes the same fictional application, **Payments API**, so a client exercising
all four together sees one coherent story rather than four unrelated fixtures:

- **One application** (`payments-api`) with **one source-control entry** — repository URL +
  base branch — served by fake IQ's `sourceControl` endpoint.
- **One report**, with **three findings** that are the three cases the decision pipeline has to
  tell apart:
  - `CVE-2022-42889` (Apache Commons Text `StringSubstitutor`) — **clearly affected**: the
    vulnerable class ships in the artifact AND the application's own bytecode references it.
    Also carries `kevData.isKev: true` — the portal's "never auto-clear" hard blocker.
  - `CVE-2021-44228` (Log4Shell, `JndiLookup`) — **genuinely ambiguous**: the vulnerable class
    ships but is not directly referenced, and a reflection escape hatch elsewhere in the same
    application (`ReflectiveConfigLoader`, via `Class.forName`/`Method.invoke`) makes that
    "not referenced" signal untrustworthy. Also carries a high EPSS score (`epssData.currentScore
    ≈ 0.975`).
  - `CVE-2015-6420` (Commons Collections `InvokerTransformer` deserialization) — **clearly not
    affected**: the bundled `commons-collections` jar ships without that specific class (as if
    minimized/shaded out), so Tier 1 proof clears it regardless of remediation status. Its
    component also has **no fix available** — the remediation endpoint returns an empty
    `versionChanges` array for it, Sonatype's own documented shape for "nothing to recommend."
- **A real, parseable Spring Boot fat JAR** (`data/sample-artifact.jar`), built with the
  existing test factories in `backend/tests/artifact/factories.py`
  (`make_spring_boot_jar`/`make_jar`/`make_class_file`) — not a stub. Its seven bundled
  libraries' SHA-1 hashes are exactly the component hashes fake IQ's raw report lists, so
  `app.provenance.fingerprint.compare` returns `Verdict.MATCH` on the happy path — the
  "component hashes MATCH the artifact" requirement in the Task 7 brief.
- **Fake Bitbucket** serves the same application's source tree (`PaymentService.java`,
  `ReflectiveConfigLoader.java`, `pom.xml`), so a symbol search for `StringSubstitutor` finds
  the exact reference the artifact's own constant-pool scan does.
- **Fake Bedrock** returns a canned, closed-enum adjudication (state / justification /
  confidence / evidence_refs / missing_evidence) for each of the three CVEs above, selected by
  looking for the CVE id inside the request body, plus a **default abstain** response
  (`confidence: insufficient_evidence`) for anything else. The `CVE-2021-44228` (ambiguous)
  case is itself an abstain — see "Why the fake Bedrock is keyed the way it is" below. Without
  a canned abstain, the human-review path this confidence value routes to would never be
  exercised against real HTTP at all.

### Regenerating the sample artifact

`data/sample-artifact.jar` is a **checked-in binary fixture**, built once rather than freshly
by each fake process. This is deliberate: `zipfile.ZipFile.writestr()` stamps every entry with
the current wall-clock time unless told otherwise, so calling the factories fresh on every
container start would change the artifact's bytes — and therefore every SHA-1 derived from it
— on every restart, breaking the exact hash agreement between fake IQ and fake JFrog that the
provenance-match scenario depends on. If the sample scenario ever needs to change, regenerate
the jar and every hash in `data/iq.json`/`data/jfrog.json` together, from the same run, using
`backend/tests/artifact/factories.py` — never hand-edit a hash.

### Why the fake Bedrock is keyed the way it is

There is no model behind `fakes/bedrock/`, so it cannot understand a prompt. It looks for a
known CVE id as a literal substring of the JSON-serialized request body and returns that CVE's
canned verdict; anything it doesn't recognise — including a request that never mentions any of
the three sample CVEs — gets the default abstain verdict. This is a fake-specific convention I
chose, not a claim about how the real Bedrock adjudicator prompt will be shaped in Task 8+; a
real client's prompt only has to mention its own finding's CVE id somewhere in the request for
this to keep working.

## Linting

`fakes/` is **excluded** from `backend`'s ruff/mypy scope (`just lint` runs
`ruff check app tests && mypy app`, both scoped to `backend/`, and `fakes/` lives outside
`backend/` entirely, so it was never in scope by default). This is a deliberate choice, not an
oversight — noted in a comment in `backend/pyproject.toml` next to `[tool.ruff]`. Reasons:

1. `fakes/` is disposable scaffolding with its own (much looser) bar — it doesn't ship, isn't
   imported by the product, and doesn't need to satisfy `mypy --strict` against FastAPI's
   dynamically-typed request/response handling to do its job.
2. Holding it to the same bar as `backend/app/` would spend effort on code whose entire purpose
   is to be deleted once the real adapters are proven against the real systems at work.

That said, this code was written cleanly and type-annotated throughout — the exclusion is about
not *gating* on it, not license to be sloppy.

## Networking

Each `vex-fake-*` service (see `compose.yaml`) joins both `proxy` and `dev-network` — the two
networks shared across every stack on this host — with **no Traefik labels**, since these are
never meant to be reachable from outside this host. Host ports `9101`-`9104` are published to
match `app/config.py`'s `fake_iq_url`/`fake_jfrog_url`/`fake_bitbucket_url`/`fake_bedrock_url`
defaults exactly, so both `just dev-api` (host venv) and a bare `pytest`/`curl` reach them at
plain `http://localhost:910x` with no `.env` changes required. Service names are prefixed
`vex-fake-` per house convention (see `~/.claude/CLAUDE.md`'s networking section) so they don't
collide with another stack's identically-named service on either shared network.

## Where I was not certain of the real vendor's exact shape

The Task 7 report (`.superpowers/sdd/2026-09-01-portal-foundations/task-7-report.md`) has the
full list with sourcing. The short version: the Nexus IQ vulnerability-detail, policy-waiver,
source-control, and component-remediation shapes were checked against Sonatype's own published
REST API documentation and are high-confidence; the raw/policy report's *top-level* fields
beyond the `components` array (in particular, whether a report carries commit/branch at all)
were not confirmed anywhere, and `docs/design.md` itself already flags this as unresolved.
Bitbucket Data Center's code-search response shape is the least-confirmed of the four — the
endpoint path and general request shape are documented, but no full example response JSON
could be found.
