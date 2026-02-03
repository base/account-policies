# Policy documentation

This directory contains short, integrator-oriented docs for individual policies as they evolve.

The goal is to make it easy to answer:

- What capability does this policy provide?
- Who is trusted to do what (account vs executor vs relayer)?
- What config is committed at install time, and what data is required at execution time?
- What invariants/limits does the policy enforce?

## AOA policy family

Some policies in this repo are “Automated On-chain Actions” (AOA) policies: they share a common configuration + authorization pattern (account chooses an **executor**, executor signs execution intents, any relayer can submit).

- See `aoa-policies.md`

## Current policies

- `morpho-lend-policy.md`
- `morpho-loan-protection-policy.md`

