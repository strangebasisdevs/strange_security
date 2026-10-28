# Suppression policy

This is the single policy for every repository that uses the strange_security
workflows. Repositories point here from their `CLAUDE.md` instead of restating
it. A suppression hides a finding, so each one is a reviewed decision with a
written reason.

## Semgrep

Only inline suppressions are allowed, and only in this form:

```python
# ffmpeg is run with an argument list, no shell, a fixed binary path, validated inputs only and a timeout; tests/test_transcode.py pins these guards
subprocess.run(args, shell=False, timeout=30)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
```

Rules:

- The comment is exactly lowercase `nosemgrep: <rule-id>`, inline after code on
  the same line, never bare. Semgrep also honours the short `nosem` form in any
  case, so those are rejected too, as is a standalone comment line holding only
  the suppression (Semgrep's previous-line form). So is any line with no letter
  or digit before the keyword, such as `# // ...`, `} // ...` or `*/ // ...`:
  Semgrep also reads those as covering the next line. A bare `nosemgrep` hides
  every rule on the line, including ones added later.
- One line, one rule. A line that needs two suppressions is a reason to change
  the code. Do not list several rule ids in one comment.
- The line directly above is a comment with a one-line reason. It says why the
  line is safe and names the guards that make it so. No blank line between.
  It is a real comment line: not code and not another suppression.
- Where the guards can be tested, a test pins them, so removing a guard fails CI
  before the suppression becomes wrong. For the ffmpeg example above the
  guards are: an argument list, no shell, a fixed binary path, validated inputs
  only, a timeout, and a test that pins all five.
- No file or directory excludes, no `.semgrepignore` entries for source code,
  and no `--exclude-rule`. Fix the code or suppress the one line.
- Every suppression is listed in the pull request description, with its file,
  rule id and reason, so the reviewer sees each one.

`semgrep.yml` runs `scripts/check_suppressions.py` on the caller's code and
fails on a bare, short or uppercase suppression, one with no rule id, one naming
several rules, two keywords on one line, a standalone suppression line, or one
without a reason comment on the line directly above. It understands
`<!-- -->` comments in every file, and the markers that are also code
elsewhere only for the listed file types:

- `//` and `/* */` count only in C-family, JS/TS, Go, Rust, Java, Kotlin,
  Swift, C#, PHP, Scala, Dart, HTML/Vue/Svelte and similar files (`/* */` also
  in CSS). In Python, Ruby and shell, `//` is floor division or a path.

- `#` counts only in shell, Python, Ruby, Perl, PHP, R, YAML, TOML, conf, cfg
  and ini files, Terraform/HCL, PowerShell and a few similar types, in
  `Dockerfile` and `Makefile`, and in files with no extension. In C-family and
  JS/TS files `#` is a preprocessor line or a private field, not a comment.
- `;` counts only in `.ini`, assembly, Lisp, Scheme and Clojure files.
- `%` counts only in `.tex`, `.sty`, `.erl`, `.hrl` and `.m` files.
- `--` counts only in `.sql`, `.lua`, `.hs` and Ada files.

It skips Markdown (`.md`, `.markdown`) and reStructuredText (`.rst`) files, and
the `.strange-security` checkout. It checks the form only; whether the reason
is true is the reviewer's call.

## Trivy

No suppressions, ever. Do not add `.trivyignore` entries or `trivy.yaml`
exclusions to pass the gate. Fix the finding: update the dependency or the base
image. If nothing fixed exists, the gate already ignores unfixed findings.

This policy is unchanged. The one thing that resembles an exception is not a
Trivy suppression: the digest-bound, reviewed, expiring image exceptions of
`trivy-images.yml`, described in [IMAGE_EXCEPTIONS.md](IMAGE_EXCEPTIONS.md).
They apply only to that workflow's image vulnerabilities, never to a secret,
the filesystem scan, `trivy-image.yml`, gitleaks or Semgrep, and they do not
make `.trivyignore` or `trivy.yaml` acceptable. The same goes for the image
secret allowlist described under Secrets below.

## Gitleaks

A secret finding means the credential is already exposed. Rotate it first,
then clean up. Only a reviewed false positive may go in `.gitleaksignore`, as
its exact fingerprint with a comment saying why it is not a secret. Do not
widen `.gitleaks.toml` allowlists to pass the gate.

## Secrets

A secret finding means the credential is already exposed. Rotate it first, then
clean up. A secret is never suppressed in source, never with an inline comment,
never in `.gitleaks.toml` or `.gitleaksignore` beyond the reviewed false
positive above, and never in a filesystem scan (`trivy.yml`): no `.trivyignore`
entry, no `trivy.yaml` exclusion, no Semgrep suppression.

The one exception is narrow and is not a suppression in the repository being
scanned. A secret that Trivy finds in a layer of a published image, and that is
public by design (a documented emulator or test key vendored in a third-party
library), may be allowed by an entry of the image secret allowlist
(`.github/image-secret-allowlist.json`, read only by `trivy-images.yml`). An
entry binds one finding to one image digest, layer, file, rule and line. It
carries a reason, an `https` evidence link to the public source of the value, a
named reviewer and an expiry of at most 31 days, and the gate lists it in the
job summary. If the value might be a real credential, rotate it first; it is not
allowlisted. The process is in
[IMAGE_EXCEPTIONS.md](IMAGE_EXCEPTIONS.md#known-public-secrets-the-secret-allowlist).
A pull request that adds or renews an allowlist entry is security-relevant:
review it as such.

## Reviewing

Changes to `.semgrepignore`, `.trivyignore`, `trivy.yaml`, `.gitleaks.toml` and
`.gitleaksignore`, any added `nosemgrep` line, and any added or renewed entry of
`.github/image-exceptions.json` or `.github/image-secret-allowlist.json`, are
security-relevant. Review
them as such.
