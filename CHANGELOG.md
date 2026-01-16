# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.1.0] - 2026-01-16

### Fixed

-   Fixed false positive vulnerabilities where non-vulnerable root dependencies were incorrectly flagged when vulnerable versions existed as nested dependencies
-   Improved vulnerability mapping to use npm audit's `nodes` field for accurate path-based detection
-   Added support for distinguishing between different versions of the same package in the dependency tree

### Changed

-   Enhanced `getVulnerabilitiesByRoot()` method to parse installation paths from npm audit output
-   Added `extractRootFromNodePath()` helper function with support for scoped packages and various path formats
-   Improved fallback logic for compatibility with older npm audit formats

## [1.0.2] - 2025-12-30

### Changed

-   Updated NPM packages
-   Refactored npm publish workflow for simplicity

## [1.0.0] - 2025-10-05

### Added

-   README documentation with initial release
-   Config file creation functionality
-   Threshold checks for audit validation
-   Version info support

### Initial Release

-   Initial version with core audit summary functionality
