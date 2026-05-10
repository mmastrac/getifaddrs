# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - Unreleased

### Added

- `Addresses::families` — returns an iterator over the families in the collection.

### Changed

- `Addresses::len` semantics: `len()` now returns the total number of addresses
  across all families (each entry in every per-family list counts toward the
  sum). Previously it returned the number of distinct address families (map key
  count); use `addresses.families().count()` for that behavior.
- `Addresses::iter` semantics: `iter()` now returns an iterator over the
  addresses in the collection. The address families are flattened into a single
  iterator. Use [`Address::family`] to get the family of each address, or
  [`Addresses::families`] to get the families and addresses together.

## [0.6.2] - 2026-05-10

### Changed

- Bumped windows-sys dependency to latest
