## What changes

<!-- One or two sentences, and the issue it closes, if any. -->

## Checklist

- [ ] `pytest` and `ruff check .` pass
- [ ] Mock tools only: no real side effects, and no network call except a model API from an adapter
- [ ] Fake data only: `.example` domains, invented people and accounts, `LURE-FAKE-` canaries for secrets
- [ ] New attacks carry ATLAS, ATT&CK and Arcanum codes, with the IDs verified on atlas.mitre.org and attack.mitre.org (or flagged as unverified)
- [ ] Results schema changes are additive, or bump `schema_version` and add `schema/results.v<N>.json`
- [ ] Docs updated where behavior changed
- [ ] No em dashes, no real company or product names in attacks and fixtures
- [ ] No real system prompts, keys or customer data anywhere in the diff

See [CONTRIBUTING.md](https://github.com/Err0ric/lure/blob/main/CONTRIBUTING.md). A security fix that is not public yet goes through a private advisory, not a pull request: see [SECURITY.md](https://github.com/Err0ric/lure/blob/main/SECURITY.md).
