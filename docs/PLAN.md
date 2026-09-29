# Plan

Investigate fuzzy extractors for recovering a cryptographic secret from repeated,
noisy fingerprint measurements.

- Review robust/reusable constructions and their entropy and helper-data leakage
  assumptions, starting with [Dodis et al.](https://cs-web.bu.edu/faculty/reyzin/fuzzy.html).
- Determine whether supported readers expose suitable samples. fprintd returns
  a matching status, not a sample or cryptographic authorization token.
- Prototype with public or synthetic data; measure repeatability, false acceptance
  and rejection, including sensor changes and re-enrollment.
- Evaluate stolen templates, replay, helper-data tampering, offline guessing,
  revocation and recovery.

Produce a feasibility report before considering production use. A fuzzy extractor
alone does not protect samples or recovered keys from a compromised OS.
