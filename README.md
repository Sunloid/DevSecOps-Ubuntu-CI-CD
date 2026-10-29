# practice-server

A small, **intentionally vulnerable** Node.js API plus the pieces of a real deployment around it, so you can practise the whole DevSecOps loop on your local WSL (Windows Subsystem for Linux) environment:

**find the problem → fix it → watch the pipeline go green → harden the box it runs on.**

> Never deploy this. Every credential in it is a randomly generated fake.

## What's in the box

| Path | What it is | Practise |
|---|---|---|
| `src/`, `package.json` | Express + SQLite notes API with 20+ planted flaws (tagged `[V01]`…`[V20]` in comments) | SAST, dependency scanning, secure coding |
| `.env.production`, `id_deploy`, `src/config.js` | Fake leaked credentials | Secret scanning |
| `Dockerfile`, `docker-compose.yml` | Insecure container setup (root user, fat image, secrets in ENV, privileged, docker.sock) | Image scanning, container hardening |
| `infra/main.tf` | Insecure AWS EC2 definition (reference for cloud IaC concepts) | IaC scanning |
| `.github/workflows/security.yml` | The pipeline: gitleaks, Semgrep, Trivy (deps + image), Checkov, Syft SBOM | CI security gates |
| `.semgrep/custom-rules.yml` | Extra Semgrep rules (community rules miss several of these bugs) | Writing/tuning rules |
| `server/harden.sh` | Ubuntu hardening: SSH, UFW, fail2ban, unattended-upgrades, sysctl | Server hardening on WSL Ubuntu |
| `solutions/` | Hardened Dockerfile + compose + healthcheck | Check your work |
| `FIXES.md` | Every flaw: where it is, which tool catches it, how to fix it | Answer key (try first!) |

## The pipeline in one picture

```
push / PR / weekly cron
  ├─ secrets   gitleaks      → FAIL on any leaked secret (scans full git history)
  ├─ sast      semgrep       → report everything, FAIL on ERROR severity
  ├─ deps      trivy fs      → report all, FAIL on CRITICAL that has a fix
  ├─ image     trivy image   → report all, FAIL on CRITICAL that has a fix   + SBOM (syft)
  └─ iac       checkov       → report all, FAIL only on a short list of real-exposure checks
```

Every stage uses the same two-step pattern: a **report** step that never fails (so nothing is hidden), then a **gate** step narrowed to what must block. That's how you stop a team from learning to ignore the output.

## Practice loop

```bash
# 0. tools (pinned versions, checksum-verified) + python scanners
scripts/install-tools.sh gitleaks trivy syft actionlint
pip install semgrep==1.181.0 checkov==3.3.29

# 1. see the damage - each command exits 1 on this repo
git init -q && git add -A && git commit -qm "start"
gitleaks git . --config .gitleaks.toml --redact --no-banner
semgrep scan --config p/javascript --config p/nodejs --config p/dockerfile \
  --config .semgrep/custom-rules.yml --severity ERROR --error .
trivy fs --scanners vuln --severity CRITICAL --ignore-unfixed --exit-code 1 .
checkov -d . --framework dockerfile,terraform --skip-download --quiet --compact
```

Then work through the levels below. After each fix, re-run the matching command and push a branch to watch the Actions run.

### Exercises

1. **Secrets.** Delete the leaked files and move credentials to environment variables. Then notice gitleaks *still fails* on the history. (Hint: that's the point. Why? What do you do about a secret that was already committed? → rotate it first, rewriting history second.)
2. **Dependencies.** Get `npm audit` / Trivy to zero criticals. Which findings need a version bump, and which need you to *remove the package* (and change code)?
3. **Code.** Fix the Semgrep ERRORs one at a time. For each, write a request that exploited it, confirm it works before the fix and fails after.
4. **Gaps.** Some flaws no scanner here catches (IDOR, mass assignment, missing admin check, verbose errors). Find them by reading the code, then write a test that fails now and passes after your fix.
5. **Container.** Rewrite the `Dockerfile` (multi-stage, non-root, minimal runtime image, HEALTHCHECK, no secrets in ENV/ARG, `.dockerignore`). Compare with `solutions/Dockerfile` afterwards.
6. **IaC.** Review `infra/main.tf` for cloud security patterns (SSH restrictions, IMDSv2, encrypted disk, least-privilege role) until the Checkov gate passes. This serves as reference for when you deploy to cloud infrastructure.
7. **Tuning.** Make the gate stricter (also block HIGH), then add an exception *with a reason and an expiry*. Write one new Semgrep rule for a bug of your own.
8. **Server.** Next section.

## Server hardening lab (WSL Ubuntu)

### Prerequisites

Ensure you have WSL 2 installed with Ubuntu 24.04:

```bash
# Check WSL version
wsl --list --verbose

# If needed, install Ubuntu 24.04
wsl --install Ubuntu-24.04
```

### Hardening Steps

1. **Access your WSL instance:**
   ```bash
   wsl
   sudo apt update && sudo apt upgrade -y
   ```

2. **Copy the hardening script:**
   ```bash
   # From Windows PowerShell/Command Prompt, copy the server directory to WSL
   wsl cp -r server/ ~/
   # Or if already in the repo directory in WSL, just:
   sudo cp -r server ~/
   ```

3. **Preview, apply, audit:**
   ```bash
   sudo ~/server/harden.sh plan      # shows every file it would write; changes nothing
   sudo ~/server/harden.sh apply
   sudo ~/server/harden.sh verify    # PASS/FAIL per control
   ```

4. **Verify your setup:**
   - Confirm WSL is still accessible after hardening
   - Check that firewall rules are in place
   - Verify fail2ban is running and configured

5. **Experiments worth doing:**
   - **Fail2ban:** Attempt multiple failed SSH logins (if you enabled SSH server), then check `sudo fail2ban-client status sshd`. Note: WSL typically doesn't run SSH server by default, but you can enable it for practice.
   - **UFW vs Docker:** `sudo ufw status verbose`; then run `docker run -d -p 8080:80 nginx` and try to access port 8080 from Windows host. **It's reachable even though ufw never allowed it.** Docker edits iptables directly and bypasses ufw. Fix it by binding to `127.0.0.1:8080:80`, and see why `solutions/docker-compose.yml` does that. Re-run `verify`.
   - **Unattended upgrades:** `sudo unattended-upgrade --dry-run -v` and read which origins it would pull from.
   - **SSH configuration:** Read `server/harden.sh`: why is the SSH drop-in named `00-…`? (First value wins; cloud images ship a `50-cloud-init.conf` that can re-enable passwords.)

### Optional: Enable SSH in WSL

If you want to practice SSH hardening specifically:

```bash
# Install and enable SSH server
sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl start ssh

# Configure SSH to allow key-based auth
sudo nano /etc/ssh/sshd_config
# Set: PasswordAuthentication no, PubkeyAuthentication yes

# Add your Windows SSH public key to ~/.ssh/authorized_keys
mkdir -p ~/.ssh
echo "your-public-key-here" >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

The script refuses to run if the admin user has no `authorized_keys`, validates `sshd -t` before reloading, and rolls back on failure. It is idempotent: run it twice and the second run reports everything "unchanged".

## Tuning later

- **Block or relax something:** edit the gate step of that stage in `security.yml` (`--severity`, `--check`, `--ignore-unfixed`).
- **Accept one specific finding:** add the fingerprint to `.gitleaksignore`, a Trivy ignore-file entry with `expired_at` (pass it with `--ignorefile`), `# nosemgrep: rule-id` on the line (reason on the line above), or `#checkov:skip=CKV_X:reason` beside the resource. Always write the *why*.
- **New rule for a bug your team keeps making:** add it to `.semgrep/custom-rules.yml`.

## What was and wasn't verified

Tested here, for real: the app boots and the planted bugs are exploitable (SQLi login bypass, `eval`, reflected XSS, mass assignment); gitleaks, Semgrep (with the custom rules), Checkov, Syft, hadolint, shellcheck and actionlint were run and all four gates exit 1 on this repo; `harden.sh` was validated against a real OpenSSH 9.6 `sshd -t`, fail2ban's config test and apt's config parser, and is idempotent.

**Not** tested here (the sandbox had no Docker and no access to Trivy's vulnerability DB or Semgrep's registry): the Trivy stages, the `p/…` Semgrep registry packs, `docker build`, and a real UFW/WSL run. Expect to fix small things on your first CI run; that is part of the practice. The dependency numbers were checked with `npm audit` instead (20 vulnerable packages, 4 critical: `ejs`, `lodash`, `minimist`, `node-serialize`).
