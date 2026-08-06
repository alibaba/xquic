# Test Routing Specification Delta

## ADDED Requirements

### Requirement: Endpoint Case Metadata

The repository SHALL provide machine-readable metadata for endpoint
client-to-server case tests.

#### Scenario: Route changed source path to endpoint cases

- **GIVEN** a source path that matches a module or feature route
- **WHEN** the case-test selector is asked for cases from that path
- **THEN** it returns every matching endpoint case ID declared in the case-test
  metadata
- **AND** it does not require running the full endpoint suite to discover the
  routing.

#### Scenario: Preserve legacy full-suite behavior

- **GIVEN** `scripts/case_test.sh` is invoked without a selector
- **WHEN** the script runs
- **THEN** it preserves the existing full-suite endpoint behavior until a
  separate change explicitly revises that contract.

#### Scenario: Validate metadata consistency

- **GIVEN** a case-test metadata file is committed
- **WHEN** the harness check runs
- **THEN** it verifies that case identifiers are unique, referenced modules and
  features exist, runner paths exist, and declared source paths are valid
  repository paths or globs.

### Requirement: Single Routing Authority

The harness SHALL keep module and feature ownership in
`harness/spec/harness-manifest.yml` and SHALL avoid duplicating the complete
path-to-module map in case-test documentation.

#### Scenario: Informative documents describe but do not redefine routing

- **GIVEN** a document under `harness/docs/`
- **WHEN** it explains how to find endpoint cases
- **THEN** it links to the harness manifest and case-test metadata instead of
  maintaining a competing path-to-module table.

### Requirement: Endpoint Case Selected Execution

The repository SHALL only execute selected endpoint case groups when their case
bodies have been migrated into runnable group files.

#### Scenario: Refuse pending selected execution

- **GIVEN** a changed path maps only to pending case-test groups
- **WHEN** selected endpoint execution is requested
- **THEN** the command fails clearly
- **AND** it tells the maintainer to use dry-run output as discovery evidence.

#### Scenario: Run migrated endpoint groups in parallel without port collision

- **GIVEN** multiple selected endpoint case groups are marked implemented
- **WHEN** selected endpoint execution is requested with parallel jobs
- **THEN** each scheduled group receives an isolated work directory
- **AND** each scheduled group receives a deterministic port derived from the
  configured port base.

#### Scenario: Keep legacy full-suite behavior explicit

- **GIVEN** no selector or selected execution flag is provided
- **WHEN** `scripts/case_test.sh` runs
- **THEN** it runs the legacy full endpoint suite through the compatibility
  entry point.
