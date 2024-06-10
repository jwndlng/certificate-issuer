# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.1.5] - 2024-06-10

### Changed

- Increase ACME ready retries to 10 from 5

### Fix

- Removed Error return from ACME ready after retries to gracefully clean up DNS record

## [1.1.4] - 2024-06-08

### Added

- feat(doc): Added CHANGELOG.md file to better track changes
- feat(release): Added SHA256 and MD5 to release workflow

### Fix

- fix(acme): Changed returning an error to just log the error to keep the retry mechanism