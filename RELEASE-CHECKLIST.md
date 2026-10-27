# Public Release Checklist

Use this checklist for every public AIO Malicious Extension Guard release. Do not publish a ZIP or WordPress.org SVN tag until every required gate is complete.

## Required release gates

- [ ] Set the release version in `aio-malicious-extension-guard.php` and `readme.txt`, and add a factual changelog entry.
- [ ] Run `composer run lint` and `composer test` in a WordPress/MySQL test environment.
- [ ] Confirm the GitHub Actions matrix is green for the supported PHP floor and a current PHP release.
- [ ] Manually test a clean installation, scan, baseline, approved-plugin review, alert email, evidence export, MU guard repair, quarantine, restore-without-activation, update retention, deactivation, and both uninstall retention choices.
- [ ] Review all capability checks, nonces, sanitization, escaping, filesystem path guards, and changes to scanning indicators.
- [ ] Confirm the release contains no credentials, private client data, development dependencies, or remote executable-code loading.
- [ ] Run the WordPress Plugin Check plugin against the release candidate on staging and resolve applicable findings.
- [ ] Keep the feature description factual: the plugin reduces risk and cannot guarantee protection after a hosting, administrator, deployment, or supply-chain compromise.

## WordPress.org preparation

- [ ] Validate `readme.txt` with the official WordPress.org readme validator.
- [ ] Confirm the slug is available and that the name does not conflict with a trademark.
- [ ] Ensure the directory ZIP is a complete, working production copy of the plugin.
- [ ] Publish a maintained source repository or keep all build/source materials necessary to understand the distributed code publicly available.
- [ ] Review `PRIVACY.md`, `SUPPORT.md`, and `SECURITY.md` for current contact details and policies.
- [ ] Place banner, icon, and real product screenshots in the top-level WordPress.org SVN `assets` directory, not in `trunk` or a release tag.
- [ ] Use a regularly checked AIO email address for the WordPress.org account and whitelist `plugins@wordpress.org`.

## First public release

- [ ] Submit the final ZIP for review at https://wordpress.org/plugins/developers/add/.
- [ ] After approval, commit the exact release to `/trunk` in the WordPress.org SVN repository.
- [ ] Copy that exact release to `/tags/<version>` and ensure the `Stable tag` matches.
- [ ] Commit the public listing artwork to `/assets`.
- [ ] Monitor the WordPress.org support forum and use the private security process for vulnerability reports.
