# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
The project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
and [ISO Date Format](https://www.iso.org/iso-8601-date-and-time-format.html).

See [unreleased changes] for the latest updates.

## [Unreleased]

### Fixed
- Issue #17: Certificate updater now displays information about removed certificates when the "remove expired certificate" option is executed

### Changed
- `update` method now returns a structure containing both added and removed certificates instead of just added certificates
- Enhanced installer and updater programs to show summary of certificate changes

## Version [1.0.0] - 2022-01-01

Initial Release.

[unreleased changes]: https://github.com/abapPM/ABAP-Strust/compare/1.0.0...main
[1.0.0]: https://github.com/abapPM/ABAP-Strust/releases/tag/1.0.0
