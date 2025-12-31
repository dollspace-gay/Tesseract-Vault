<!-- Project-Specific Rules -->

### Changelog Requirements

**MANDATORY**: When making user-facing changes, you MUST update [CHANGELOG.md](../../CHANGELOG.md).

#### What Requires a Changelog Entry
- New features or functionality
- Bug fixes
- Security fixes or improvements
- Breaking changes
- Deprecations
- Performance improvements
- API changes

#### What Does NOT Require a Changelog Entry
- Internal refactoring with no user-visible changes
- Documentation-only changes
- Test-only changes
- CI/build configuration changes

#### Changelog Format
Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format:

```markdown
## [Unreleased]

### Added
- New feature description

### Changed
- Modified behavior description

### Fixed
- Bug fix description

### Security
- Security improvement description
```

#### Categories
- **Added**: New features
- **Changed**: Changes in existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Vulnerability fixes
