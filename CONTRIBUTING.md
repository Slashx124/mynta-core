# Contributing to Mynta Core

Thank you for your interest in contributing to Mynta Core. This document explains how to participate in the project's development.

## How to Contribute

### Reporting Issues

Before opening an issue:
1. Search existing issues to avoid duplicates
2. Include clear steps to reproduce bugs
3. Provide relevant system information (OS, compiler, version)
4. Attach logs or error messages when applicable

Use descriptive titles and provide enough context for others to understand and verify the problem.

### Submitting Pull Requests

1. Fork the repository
2. Create a topic branch from `main`
3. Make focused, incremental changes
4. Write clear commit messages
5. Ensure tests pass locally
6. Open a pull request with a descriptive summary

#### Commit Messages

- Subject line: 50 characters max, imperative mood
- Body: Explain *what* and *why*, not just *how*
- Reference related issues: `fixes #123` or `refs #456`

#### Pull Request Guidelines

- One logical change per PR
- Do not mix formatting changes with functional changes
- Include tests for new functionality
- Update documentation if behavior changes

Prefix PR titles with the affected area:
- `Build:` — Build system changes
- `Consensus:` — Consensus-critical changes
- `Net:` — Networking code
- `RPC:` — RPC interface
- `Wallet:` — Wallet functionality
- `Tests:` — Test additions or fixes
- `Docs:` — Documentation only

## Code Review

All changes require peer review before merging. Reviewers use the following conventions:

- **ACK** — Reviewed and tested; approve merge
- **NACK** — Disagree with merging; must include technical justification
- **utACK** — Reviewed but not tested; approve merge
- **Concept ACK** — Agree with the approach; code not yet reviewed

Include the commit hash you reviewed in your comments.

## Quality Standards

All contributions must:
- Follow the project's coding style (see [doc/developer-notes.md](doc/developer-notes.md))
- Pass existing tests (`make check`)
- Not break the functional test suite
- Include tests for bug fixes (when feasible)

## Consensus-Critical Changes

Changes affecting consensus rules require:
- Prior discussion with maintainers
- A clear proposal document
- Extended review period
- Broad agreement from reviewers

Do not submit consensus changes without prior discussion. These changes affect the entire network and require careful coordination.

## Security

If you discover a security vulnerability:
- **Do not** open a public issue
- Contact maintainers privately
- Allow reasonable time for a fix before disclosure

## Refactoring

Refactoring PRs should:
- Not change behavior
- Be easy to review (keep them small)
- Separate code movement from code changes

New contributors should focus on features or bug fixes rather than large-scale refactoring.

## Communication

- Be respectful and constructive
- Assume good intent
- Focus on technical merit
- Accept that maintainers make final decisions

## License

By contributing, you agree to license your work under the MIT License, unless otherwise specified at the top of the file. Contributions must include appropriate license headers when incorporating external code.
