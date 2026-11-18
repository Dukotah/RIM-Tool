# LANE 7 report: RIM-Tool

## 1. Upstream contribution rules

- CONTRIBUTING.md is only a CC0 1.0 waiver: by opening a PR you agree your changes are released under CC0
  worldwide. There is no CLA, no DCO and no PR template.
- SECURITY.md (added 2026-11-04): report security issues privately via the Security tab ("Report a
  vulnerability"), never in a public issue or PR. A person must have reviewed the report.
- Every merged PR (#3 to #64) came from the internal team (iadgovuser26/58/59/62, chubtub). Outsiders have
  never landed an issue or a PR. Team PRs use "[#issue] Title" against an assigned issue.
- CI (`unit_tests.yml`) runs `./gradlew build` and then `src/test/scripts/run_all_tests.sh` on PRs to `main`.

None of the findings below are security issues. They are interop and conformance bugs, so a public issue is fine.

## 2. Branches

| Branch | Base | Bound for | Commit |
|---|---|---|---|
| `fix/corim-coswid-tests` | upstream/main `66934e7` | upstream PR, after an issue | `c65d2df` Add CoRIM with CoSWID system tests |
| `lane/corim-conformance` | `fix/corim-coswid-tests` | fork only | `ef2d031` Veraison interop harness + workflow, plus this report |

### A: `fix/corim-coswid-tests` (1 commit, +18/-1 lines, 1 binary fixture of 455 bytes)
Replaces `# TODO: Corim with Coswids` in `src/test/scripts/corim_comid_tests.sh` with three tests in the
file's existing style:
- TEST 9 signs `data/corim/corim_coswid_1.cbor`
- TEST 10 verifies the signature
- TEST 11 prints the result. This runs `CoRimParser`'s CoSWID (tag 505) branch, which no test covered before.

The fixture is an unsigned CoRIM (`#6.501`) whose only tag is the repo's own `data/coswid/coswid_rim_1.coswid`,
wrapped as tag 505. It uses the same wrapping RIM Tool emits for CoMIDs (see finding F1). I generated it with
cbor2 by unwrapping the coswid file's `#6.1398229316(bstr)` and storing `bstr(0xd901f9 || map)` in the tags array.

The test catches real breakage: when I corrupted the CoSWID map header in the fixture, TEST 11 failed with
`Cannot deserialize value of type LinkedHashMap ... from Integer value`.

I left `# TODO: Corim with CoTLs` alone. `CoRimParser` throws "CoTL data (CBor Tag 508) ... is not currently
supported", so the only test you could write today is an expected failure. I did not add a test that fails.
The parser needs work first (issue text below).

### B: `lane/corim-conformance` (fork only)
- `src/test/interop/corim-interop/` is a Go helper that pins `github.com/veraison/corim@43f4a78` (2026-11-13).
  Its subcommands:
  - `rewrap -to spec|legacy` re-encodes the tags array.
  - `add-cotl` appends a CoTL built with Veraison's `cotl` package.
  - `cose-verify` checks a COSE_Sign1 with go-cose only.
  - `jwk` converts the test P-521 key to a JWK for cocli.
- `src/test/interop/veraison_interop_tests.sh` has 12 cases. Each known mismatch is an *expected failure that
  must keep failing with the same message*. If upstream fixes one, the case turns red and someone updates the
  expectation.
- The Veraison inputs (`src/test/interop/veraison/`) come from the cocli test data (Apache-2.0):
  `comid-dice-refval.cbor` and `coswid/1.cbor`, plus two corim templates and the meta template.
- `.github/workflows/veraison_interop.yml` runs on `lane/**` pushes. It installs cocli `499dc19` (2026-10-13),
  then runs `./gradlew build`, the existing system tests and the interop cases.

## 3. Findings (the valuable output of B)

I checked every claim against the draft's CDDL (ietf-rats-wg/draft-ietf-rats-corim `cddl/`, commit
f96f0ce3bb, 2026-11-01) and reproduced it with the tools above.

| # | Finding | Draft says | Evidence (case) |
|---|---|---|---|
| F1 | RIM Tool (HIRS_Utils `CoRimConfig.build`) writes each tag as `bytes .cbor #6.506(map)`, and `CoRimParser` only accepts that form | `tagged-concise-mid-tag = #6.506(bytes .cbor concise-mid-tag)`, the same for 505 and 508 | R1/R2: cocli `cannot unmarshal byte string into Go value of type cbor.Tag`. V2: RIM Tool on a cocli CoRIM fails with `Cannot invoke "[B.clone()" because "this.content" is null`. After `rewrap`, R4 and V4 pass in both directions, so the wrapping is the only blocker for CoMID content |
| F2 | `CoRimParser` casts corim-id to `String` | `$corim-id-type-choice /= tstr / uuid-type` | V3: `class [B cannot be cast to class java.lang.String`. cocli writes UUID ids by default |
| F3 | The CoSWID parser assumes a binary tag-id | RFC 9393 `tag-id: text / bstr .size 16` | V5: `broken Base64 encoding: Illegal character '.'` on cocli's `1.cbor` |
| F4 | `data/corim/corim_1.json` uses entity roles `[0, 1]`, which `CoRimConfig` accepts and the parser prints as "tag-creator" | `$corim-role-type-choice` defines only `manifest-creator: 1` and `manifest-signer: 2` | R5: cocli `unknown role 0` |
| F5 | `coswid-tags` in a CoRIM config is never encoded. A populated entry fails with the misleading `Error Creating Signature ... Invalid field ...: software-name` (even with `-u`). `[{}]` is silently dropped (the output is byte-identical to the config without it). A config with only `coswid-tags` writes an empty tags array | `tags: [ + $concise-tag-type-choice ]` must not be empty | manual probe, section 4 |
| F6 | CoTL (508) is rejected | defined in section 6 | T2. cocli itself does not display CoTL either (T1: `unmatched CBOR tag: 508`) |
| F7 | The vendored `data/corim/veraison/*.cbor` predate the current Veraison encoding (untagged corim-map, old tag wrapping). Current cocli rejects them with `did not see unsigned CoRIM tag`. Current RIM Tool rejects today's Veraison `corim/testcases/signed-example-corim.cbor` | n/a | manual probe |
| F8 (minor) | The test signer key is P-521 but RIM Tool signs with ES384 (-35). go-cose accepts this; RFC 9053 pairs ES384 with P-384 | n/a | R3 prints `verified: alg ES384, key curve P-521` |

Things that do interoperate today:
- The COSE layer works in both directions. go-cose verifies RIM Tool signatures (R3), and RIM Tool verifies
  cocli-signed CoRIMs (V1).
- The protected header and payload `#6.501` match the draft.
- CoMID content survives a re-wrap in both directions (R4, V4).

## 4. Evidence (WSL Ubuntu, Temurin 25.0.5, Gradle 9.3.1 wrapper, go 1.25.5)

Build (WSL-local copy `~/build/RIM-Tool`, built with `-x updateGitSubmodules` because the copy is not the git checkout):
```
$ ./gradlew build -x updateGitSubmodules --no-daemon
> Task :checkstyleMain / :checkstyleTest / :test / :spotbugsMain / :spotbugsTest / :check
BUILD SUCCESSFUL in 4m 26s
```
Baseline `run_all_tests.sh` on upstream/main: 7 scripts. The first run reported `FAILED cose_tests.sh` while
the machine was under heavy memory pressure (another lane's Ghidra decompiler held 13 GB). Two re-runs passed
all 7, including `cose_tests.sh` on its own ("All COSE tests passed."). I treat that failure as flaky, not as a
regression.

Branch A:
```
$ ./src/test/scripts/corim_comid_tests.sh
PASSED: RIM test "CoRim TEST 1: CoRim print"
...
PASSED: RIM test "CoRim TEST 9: CoRim sign with CoSWID"
PASSED: RIM test "CoRim TEST 10: CoRim verify with CoSWID"
PASSED: RIM test "CoRim TEST 11: CoRim print with CoSWID"
All CoRIM tests passed.
```
F5 probe:
```
coswid-tags: [coswid_rim_1.json] -> Error Creating Signature: ... Invalid field contained in CoRIM configuration file: software-name
coswid-tags: [{}]                -> written; cmp with corim_1.json output: identical (coswid-tags dropped)
only coswid-tags: [{}]           -> written, 190 bytes, tags array empty
```
Branch B, local:
```
$ src/test/interop/veraison_interop_tests.sh
== Fixtures
built 9 files
== RIM Tool -> Veraison
PASSED: R1 cocli decodes RIM Tool unsigned CoRIM (known mismatch: cannot unmarshal byte string into Go value of type cbor.Tag)
PASSED: R2 cocli decodes RIM Tool signed CoRIM (known mismatch: error decoding CoRIM)
PASSED: R3 go-cose verifies RIM Tool COSE_Sign1 signature
PASSED: R4 cocli decodes RIM Tool CoRIM once tags are re-wrapped to #6.506(bstr)
PASSED: R5 cocli accepts corim_1.json entity roles [0, 1] (known mismatch: unknown role 0)
== Veraison -> RIM Tool
PASSED: V1 RIM Tool verifies cocli-signed CoRIM signature
PASSED: V2 RIM Tool prints cocli CoRIM (CoMID) (known mismatch: because "this.content" is null)
PASSED: V3 RIM Tool prints cocli CoRIM with uuid corim-id (known mismatch: cannot be cast to class java.lang.String)
PASSED: V4 RIM Tool prints cocli CoMID once tags are re-wrapped to bstr(#6.506)
PASSED: V5 RIM Tool parses CoSWID with text tag-id (known mismatch: broken Base64 encoding)
== CoTL (tag 508)
PASSED: T1 cocli displays a CoTL (known mismatch: unmatched CBOR tag: 508)
PASSED: T2 RIM Tool parses a CoTL (known mismatch: CoTL data (CBor Tag 508) found within the CoRIM data is not currently supported)
All Veraison interop tests passed.
```
`go vet`, `gofmt -l` and `shellcheck -S warning` are all clean.

Fork CI, run https://github.com/Dukotah/RIM-Tool/actions/runs/44247636407 on `ef2d031`: **success**. The run
includes branch A's tests, because `run_all_tests.sh` runs `corim_comid_tests.sh`.
```
BUILD SUCCESSFUL in 1m 34s
Number of tests ran    = 7
Number of tests passed = 7
Number of tests failed = 0
PASSED: T2 RIM Tool parses a CoTL (known mismatch: ...)
All Veraison interop tests passed.
```

## 5. Competing work check

- `gh pr list -R nsacyber/RIM-Tool --state all -L 50`, run at the start and again at the end: the only open
  PR is #66 (log4j removal: build.gradle, versions.toml, hirs pointer). It does not overlap. No spray accounts.
- The only open issue is #65 (assigned, log4j). Searches for "coswid" and "corim" turned up nothing on CoSWID
  tests or interop. A HIRS search for "veraison" and "CoTL" found no issues.

## 6. Draft upstream text

Upstream has never accepted an outsider, so open the issue first, then the PR only if a maintainer responds.

### Issue 1 (RIM-Tool): tests for CoRIM with CoSWID
**Title:** Add system tests for CoRIM with CoSWID (TODO in corim_comid_tests.sh)

**Body:**
> `src/test/scripts/corim_comid_tests.sh` ends with `# TODO: Corim with Coswids` and `# TODO: Corim with CoTLs`.
> Right now only CoMID payloads are covered, so the CoSWID branch of `CoRimParser` (tag 505) never runs in CI.
>
> I have a small change ready that adds tests 9 to 11 (sign, verify, print a CoRIM that holds a CoSWID). It
> uses one new 455-byte fixture, `data/corim/corim_coswid_1.cbor`, built from the existing
> `data/coswid/coswid_rim_1.coswid`. Would you take it as a PR?
>
> I did not add a CoTL test, because `CoRimParser` currently rejects tag 508 ("not currently supported"). That
> would only be an expected-fail case until the parser supports CoTL.

### PR (after the issue is acknowledged), from `fix/corim-coswid-tests`
**Title:** Add CoRIM with CoSWID system tests

**Body:**
> Closes the `TODO: Corim with Coswids` in `src/test/scripts/corim_comid_tests.sh` (issue #N).
>
> - New fixture `data/corim/corim_coswid_1.cbor`: an unsigned CoRIM (tag 501) whose single tag is
>   `data/coswid/coswid_rim_1.coswid` wrapped as concise-swid-tag (505). It uses the same tag wrapping RIM Tool
>   emits for CoMIDs.
> - TEST 9 signs it, TEST 10 verifies it, TEST 11 prints it, which runs the CoSWID branch of `CoRimParser`.
>   Corrupting the CoSWID in the fixture makes TEST 11 fail.
> - The CoTL TODO is left in place, since tag 508 is rejected by the parser today.
>
> `./gradlew build` and `src/test/scripts/run_all_tests.sh` pass locally on JDK 25.
>
> 🤖 Generated with [Claude Code](https://claude.com/claude-code)

### Issue 2 (RIM-Tool; the parser and config code live in HIRS_Utils, so maintainers may move it): CoRIM interop with draft-ietf-rats-corim / Veraison
**Title:** CoRIM tags are encoded as bstr(#6.506(...)) instead of #6.506(bstr), so CoRIMs do not interoperate with Veraison

**Body:**
> RIM Tool CoRIMs cannot be read by the Veraison reference tooling, and RIM Tool cannot read CoRIMs that cocli
> creates. I checked against the current draft CDDL (`ietf-rats-wg/draft-ietf-rats-corim`, `cddl/`) using
> cocli 499dc19 and github.com/veraison/corim 43f4a78.
>
> 1. **Tag wrapping.** The draft defines `tagged-concise-mid-tag = #6.506(bytes .cbor concise-mid-tag)`, and the
>    same pattern for 505 (CoSWID) and 508 (CoTL). `CoRimConfig.build()` writes `bytes .cbor #6.506(map)`, and
>    `CoRimParser` / `CborTagProcessor` only accept that form.
>    - `cocli corim display` on a `rim create -r corim_comid -u` output fails with
>      `cannot unmarshal byte string into Go value of type cbor.Tag`.
>    - `rim print -r corim_comid` on a cocli-signed CoRIM fails with
>      `Cannot invoke "[B.clone()" because "this.content" is null`.
>    - When only the tags array is re-wrapped, both tools read each other's CoMID content correctly.
> 2. **corim-id as uuid.** `$corim-id-type-choice` is `tstr / uuid-type`. `CoRimParser` does
>    `(String) corimMap.get(0)` and fails with `class [B cannot be cast to class java.lang.String` on a
>    UUID id, which is cocli's default.
> 3. **CoSWID text tag-id.** RFC 9393 allows `tag-id: text / bstr .size 16`. A CoSWID with a text tag-id
>    fails with `Cannot access contents of TextNode as binary due to broken Base64 encoding`.
> 4. **CoRIM entity roles.** `$corim-role-type-choice` defines only `manifest-creator: 1` and
>    `manifest-signer: 2`. `data/corim/corim_1.json` uses `"role": [ 0, 1 ]`. `CoRimConfig` accepts 0 and the
>    parser prints it as "tag-creator" (a CoMID role). cocli rejects it with `unknown role 0`.
> 5. **coswid-tags in a CoRIM config.**
>    - The field is deserialized but never encoded. `"coswid-tags": [{}]` produces output byte-identical to the
>      same config without it.
>    - A populated entry fails with `Error Creating Signature: ... Invalid field contained in CoRIM
>      configuration file: software-name`, even with `-u`.
>    - A config with only `coswid-tags` writes an empty `tags` array, but the draft requires
>      `[ + $concise-tag-type-choice ]`.
> 6. **Test vectors.** `data/corim/veraison/*.cbor` predate Veraison's current encoding. Current cocli rejects
>    them with `did not see unsigned CoRIM tag`.
>
> The COSE layer already interoperates in both directions: go-cose verifies RIM Tool signatures and RIM Tool
> verifies cocli-signed CoRIMs. A small note: the P-521 test key is used with ES384. RFC 9053 pairs ES384 with
> P-384, and ES512 with P-521.
>
> I can share a script that reproduces all of the above.

## 7. Land probability

- **A: Low-Med.** The change is tiny and closes the maintainers' own TODO, but this repo has never merged an
  outsider. The fixture also uses the legacy tag wrapping (F1), so a maintainer who fixes F1 has to regenerate
  it.
- **Issue 2: Med for acknowledgement.** The findings are concrete and spec-cited, but the fixes belong to the
  HIRS team's parser and they set their own roadmap.
- **Owner next steps:**
  1. Open Issue 1 and Issue 2 by hand (the human-review rule in SECURITY.md signals a dislike of bulk AI
     reports).
  2. Open the PR from `fix/corim-coswid-tests` only if a maintainer replies.
  3. Keep `lane/corim-conformance` on the fork. If HIRS fixes F1 to F6, the matching cases go red, and
     flipping them to `interop_pass` is the follow-up.
