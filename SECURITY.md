# Security and publishing

This application is intended for a trusted management network. It is not hardened
for direct exposure to the public Internet.

## Credentials and deployment

- Fresh databases create an `admin` account with a random password in
  `data/.bootstrap_password` (permissions 0600), unless `DEFAULT_PASSWORD` is set.
  Read it locally with `sudo cat data/.bootstrap_password`, sign in, then change
  the password and delete this bootstrap file. Existing accounts are preserved;
  upgrading does not rotate old passwords. Replace any old `admin` password.
- Protect the entire `data/` directory and its backups. Fernet keys live beside
  the encrypted database, so a copy of both can decrypt router credentials.
- Keep `.env`, databases, router exports, backups and encryption/signing keys out
  of Git. `.gitignore` excludes these; `.dockerignore` uses an allowlist of runtime
  inputs so local data cannot enter new image layers. Images built before this
  change may still contain data: do not publish those images.
- Put the web interface behind HTTPS and set `SESSION_COOKIE_SECURE=true` for
  HTTPS deployments. Restrict TCP 8080 and UDP 2055 at the host firewall. UDP
  exporter IP allowlisting does not authenticate packets.
- RouterOS API currently uses unencrypted TCP (8728), and SNMP uses v2c. Use a
  dedicated management network/VPN and least-privilege router credentials. The
  application does not yet implement API TLS or SNMPv3 collection.
- Alert destinations are operator-configured URLs; operators must be trusted.
  Router backups and device logs can contain sensitive configuration.
- The container currently runs as root to support existing bind-mount ownership.
  Protect access to the Docker daemon and host data directory. Third-party UI
  assets other than the bundled Chart.js still load from CDNs.

## Before a public push

1. Run `git status --short`, `git diff --check`, and review `git diff --cached`.
2. Ensure `git ls-files data .env` prints nothing. Ignore rules do not remove
   already-tracked secrets or historical commits.
3. Run a secret scanner against both the working tree and Git history. If a real
   credential was committed, revoke/rotate it before publishing; deleting the
   current file alone is insufficient.
4. Run `python -m unittest discover -s tests -v` and a dependency audit:
   `pip-audit -r requirements.txt`. CI repeats the suite and dependency audit.
5. Publish a newly rebuilt image only. Never include your local `data/` directory
   in release archives. Keep licenses for bundled third-party assets.

Automated checks and the changes here are not a complete penetration test.
Report security issues privately to the repository maintainer; do not include
live credentials, packet captures, or database files in a public issue.
