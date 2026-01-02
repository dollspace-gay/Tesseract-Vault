# Governance

This document describes the governance model for Tesseract Vault.

## Overview

Tesseract Vault uses a **Benevolent Dictator For Life (BDFL)** governance model. This is a common model for smaller open source projects where one person has final authority over all decisions.

## Roles

### Project Lead (BDFL)

**Current Lead:** [@dollspace-gay](https://github.com/dollspace-gay)

The Project Lead has final authority on all project decisions, including:

- **Technical direction** - Architecture, features, and implementation approaches
- **Release decisions** - When to release, what to include
- **Contribution acceptance** - Which pull requests to merge
- **Community standards** - Code of conduct enforcement
- **Security responses** - Handling vulnerability reports

### Contributors

Anyone who submits a pull request, reports an issue, or otherwise contributes to the project. Contributors are expected to:

- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)
- Sign off commits per the [DCO](CONTRIBUTING.md#developer-certificate-of-origin-dco)
- Follow contribution guidelines in [CONTRIBUTING.md](CONTRIBUTING.md)

### Maintainers

Currently, the Project Lead is the sole maintainer. As the project grows, additional maintainers may be added with specific responsibilities:

- **Code review** - Reviewing and approving pull requests
- **Issue triage** - Categorizing and responding to issues
- **Release management** - Preparing and publishing releases
- **Security response** - Handling vulnerability reports

## Decision Making

### Day-to-Day Decisions

The Project Lead makes routine decisions about:
- Merging pull requests
- Prioritizing issues
- Minor feature additions
- Bug fixes

### Significant Decisions

For significant changes (breaking changes, major features, architectural shifts), the Project Lead will:

1. Open a GitHub Issue or Discussion to gather community input
2. Allow reasonable time for feedback (typically 1-2 weeks)
3. Consider all input before making a final decision
4. Document the rationale for the decision

### Dispute Resolution

If there is disagreement about a decision:

1. **Discussion** - Parties discuss the issue in the relevant GitHub Issue
2. **Mediation** - The Project Lead may request additional input from the community
3. **Final Decision** - The Project Lead makes the final call

The Project Lead's decision is final. Contributors who strongly disagree always have the option to fork the project under the MIT license.

## Succession

If the Project Lead becomes unable to continue:

1. The Project Lead should designate a successor if possible
2. If no successor is designated, the most active maintainer(s) may assume leadership
3. The project may transition to a collective governance model if appropriate

## Changes to Governance

This governance model may be updated as the project evolves. Changes will be:

1. Proposed via pull request
2. Open for community comment
3. Decided by the Project Lead

## Contact

- **General questions:** Open a GitHub Issue
- **Security issues:** See [SECURITY.md](SECURITY.md)
- **Governance questions:** Open a GitHub Discussion or Issue

---

*This governance model is inspired by common open source practices and may evolve as the project and community grow.*
