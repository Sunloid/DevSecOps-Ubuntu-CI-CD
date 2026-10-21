# FIXES.md - answer key (try the exercises first)

"Caught by" is what actually fired when this repo was scanned. **Blocking** = fails the gate in `security.yml`; **reported** = visible in the report but doesn't block; **none** = no scanner here finds it, so you need tests or code review.

## Application code

| ID | Flaw (where) | Caught by | Fix |
|---|---|---|---|
| V01 | SQL injection: login and search build SQL by string concatenation (`server.js` login, `/api/notes/search`) | Semgrep custom rule `sqli-better-sqlite3` - **blocking** | Constant SQL + bound values: `db.prepare('SELECT * FROM users WHERE username = ?').get(username)`, then compare the password hash in code. For `LIKE`, bind `'%' + escaped + '%'`. |
| V02 | IDOR: any user reads any note by id (`GET /api/notes/:id`) | **none** | Put ownership in the query: `WHERE id = ? AND owner_id = ?`; return 404 (not 403). Write a two-user test. |
| V03 | Stored XSS: `<%- note.body %>` in `views/note.ejs` | Semgrep community rule (low confidence) - reported | `<%= %>` escapes. Add a CSP (`helmet`). |
| V04 | Reflected XSS: `res.send('<h1>' + req.query.q + …)` | Semgrep custom rule `reflected-xss-res-send` - **blocking** | Render through an escaping template, or send JSON. |
| V05 | Command injection: `exec('nslookup ' + host)` | Semgrep `command-injection-exec` - **blocking** | No shell: `dns.promises.lookup(host)` after validating `host` against a hostname regex. |
| V06 | Path traversal: `path.join(uploadDir, req.params.name)` + `fs.readFile` | Semgrep `path-traversal-fs` - **blocking** | Strict filename regex + extension allowlist, then `res.sendFile(name, { root: uploadDir, dotfiles: 'deny' })`. |
| V07 | SSRF: `axios.get(req.query.url)` | Semgrep `ssrf-outbound-request` - **blocking** | Never take a URL from the caller. Take a *key* and look it up in a server-side allowlist. |
| V08 | Insecure deserialization: `unserialize(...)` from `node-serialize` (RCE) | Semgrep `node-serialize-unserialize` + Trivy/npm audit (critical) - **blocking** | `JSON.parse`, validate the shape, copy known fields into a new object, and remove the package. |
| V09 | Passwords hashed with unsalted MD5 | Semgrep `weak-hash-md5-sha1` - reported | `bcryptjs`/`argon2` (cost ≥ 12). Existing hashes need a rehash-on-login migration. |
| V10 | Hard-coded JWT secret, `jwt.verify` without `algorithms`, tokens never expire | Semgrep `jwt-verify-without-algorithms`, `hardcoded-secret-in-object` - **blocking** | Secret from `process.env` (fail at boot if < 32 chars). `verify(t, s, { algorithms: ['HS256'], issuer, audience })`, `expiresIn: '15m'`. |
| V12 | `eval(req.query.expr)` in `/api/calc` | Semgrep `code-string-concat` - **blocking** | Delete the endpoint (or use a real expression parser). |
| V13 | Open redirect: `res.redirect(req.query.next)` | Semgrep community rule - reported | Accept only same-site paths: `/^\/(?![/\\])[\w\-./?=&%]*$/`, otherwise `/`. |
| V14 | Mass assignment (`role` from the body on register) and no admin check on `/api/admin/*` | **none** | Never read `role` from input. `requireRole('admin')` that re-reads the role from the DB, not from the token. |
| V15 | Prototype pollution: `_.merge({}, defaults, req.body)` | Semgrep `prototype-pollution-lodash-merge` - reported | Whitelist-copy known keys with validation; update lodash. |
| V16 | `cors({ origin: '*', credentials: true })` | Semgrep community rule - reported | Exact-match allowlist of origins. |
| V17 | Error handler returns `err.stack` | **none** | Log details server-side, return a generic message. |
| V18 | No `helmet`, no rate limiting, 50 MB JSON body limit | **none** | `helmet()`, `express-rate-limit` (strict on `/auth/*`), `express.json({ limit: '100kb' })`. |
| V19 | Vulnerable dependencies (`ejs 2.7.1`, `lodash 4.17.11`, `minimist 1.2.0`, `node-serialize 0.0.4`, `axios 0.21.0`, `express 4.16.0`, …) | Trivy fs / `npm audit`: 20 packages, 4 critical - **blocking** | Upgrade; remove what is unmaintained. Commit the lockfile. |
| V20 | Secrets in `src/config.js`, `.env.production`, `id_deploy`, Dockerfile `ENV`, compose `environment` | gitleaks - **blocking** | Delete, **rotate the real credentials**, read from the environment, add a `.gitignore` entry and `.dockerignore`. |

## Container, compose, cloud

| ID | Flaw | Caught by | Fix |
|---|---|---|---|
| V21 | Old full-size base image (`node:22.2.0-bookworm`: compilers, git, curl…) | Trivy image (OS CVEs) | Multi-stage build; distroless or `-slim` runtime on a current tag. |
| V22 | Secrets in `ARG`/`ENV` end up in image history | hadolint `DL3064` (not wired in CI; try it) | Pass secrets at runtime (env/secret manager), never at build time. |
| V23 | `COPY . .` ships `.env.production`, `id_deploy`, `.git` | **none** | `.dockerignore` and copy only what you need. |
| V24 | `npm install`, dev dependencies in the image | **none** | `npm ci --omit=dev`. |
| V25 | `EXPOSE 22` | Checkov `CKV_DOCKER_1` - **blocking** | Remove it. Use `docker exec` / SSM. |
| V26 | No `USER` - runs as root | Checkov `CKV_DOCKER_3` + Semgrep `missing-user` - **blocking** | `USER 65532:65532` (distroless `nonroot`). |
| V27 | No `HEALTHCHECK` | Checkov `CKV_DOCKER_2` - reported | Healthcheck (a tiny Node script when there's no curl). |
| V28 | Compose: `privileged: true`, docker.sock mounted, `user: root`, `"3000:3000"` on all interfaces, inline secrets | Semgrep custom compose rules - **blocking** (privileged, socket), reported (root, port) | `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, `127.0.0.1:3000:3000`, env from outside the file. See `solutions/docker-compose.yml`. |
| V29 | Terraform: SSH open to 0.0.0.0/0, IMDSv1, unencrypted disk, `AdministratorAccess` role, plaintext password in user-data | Checkov - 8 failed checks; `CKV_AWS_24/79/274` **blocking** | SSH from your /32, `http_tokens = "required"`, `encrypted = true`, a least-privilege role, key-only SSH. |

## Things worth noticing

- **gitleaks still fails after you delete the files** because the secret is in git history. Rotation is the real fix; history rewrite is cleanup.
- **The default Semgrep community rules miss several of these bugs** (login SQLi, SSRF, `node-serialize`, JWT without `algorithms`) and skip modern compose files that have no `version:` key. That's why `.semgrep/custom-rules.yml` exists. Never assume a scanner covers your stack: plant a known bug and check that it fires.
- **Four flaws have no scanner at all** (V02, V14, V17, V18). Tests and review are not optional.
