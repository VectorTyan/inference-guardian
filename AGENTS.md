# Inference Guardian maintenance

- Keep production configuration, image archives, credentials, runtime data, reports and developer regression fixtures in the ignored local/ tree. Use documentation address ranges in committed examples.
- For changes to packaging, profile selection or deployment identity, read docs/operations.md. Build the site package with `python3 -B scripts/make_bundle.py --delivery-dir local/delivery`. Compare generated configurations and adoption fingerprints before changing a catalog used for an existing installation.
- For changes to recovery or lifecycle code, read docs/recovery.md. Keep action receipts across interruption, reconcile unknown results, and retain the model containers pinned by adoption. Exercise and deployment writes require an operator-approved maintenance window.
- Preserve public Python imports, CLI options, host Python 3.7 compatibility and on-disk contracts. Run `python3 -B scripts/generate_external_profiles.py --check`. On a maintainer checkout with local fixtures, run `python3 -B local/validation/run_tests.py` under Linux/WSL using Python 3.11 or later.
- Record version changes in docs/release-notes.md. Deliver changes in reviewable commits. Report offline verification separately from field acceptance. Include the three field delivery files and the observe upgrade command when delivering a site release.
