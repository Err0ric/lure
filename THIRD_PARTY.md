# Third-party material

Lure is licensed under Apache 2.0 (see [`LICENSE`](LICENSE)). It includes
the third-party material below, each under its own license.

## Arcanum Prompt Injection Taxonomy

Based on the Arcanum Prompt Injection Taxonomy by Jason Haddix, Arcanum Information Security (arcanum-sec.com).

Lure is not affiliated with or endorsed by Arcanum Information Security.

**Citation:** Haddix, J. (2026). *Arcanum Prompt Injection Taxonomy* (v1.6.1). Arcanum Information Security. https://www.arcanum-sec.com/pitax

| | |
| --- | --- |
| What Lure uses | `taxonomy.json`: the codes and names of its intents, techniques, evasions and inputs |
| Where | [`lure/arcanum/`](lure/arcanum/): `taxonomy.json` and `LICENSE.md`, unmodified copies |
| Source | https://github.com/Arcanum-Sec/arc_pi_taxonomy, commit `e02cf5b6e202f195c6b6c01484e99519f797acc6` (v1.6.1), retrieved 2026-10-24 |
| Sites | https://www.arcanum-sec.com/pitax and https://arcanum-sec.github.io/arc_pi_taxonomy/ |
| License | Creative Commons Attribution 4.0 International (CC BY 4.0), https://creativecommons.org/licenses/by/4.0/ |
| Copyright | © 2024-2026 Jason Haddix, Arcanum Information Security |
| Changes | None to the data. Lure adds its own mapping of attacks to the codes (`arcanum:` in each attack file) and a coverage report ([`docs/arcanum-coverage.md`](docs/arcanum-coverage.md)) |

Hashes and update steps: [`lure/arcanum/SOURCE.md`](lure/arcanum/SOURCE.md).

## SARIF 2.1.0 JSON schema (tests only)

`tests/data/sarif-schema-2.1.0.json`, an unmodified copy of the OASIS
standard's schema, used to validate Lure's SARIF output in tests. It is not
part of the installed package. Source, hash and the OASIS notices:
[`tests/data/sarif-schema-2.1.0.NOTICE.md`](tests/data/sarif-schema-2.1.0.NOTICE.md).
