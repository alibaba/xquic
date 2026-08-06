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

### Requirement: Unit-Test Parallel Safety

The repository SHALL only enable parallel unit-test execution for suites whose
shared resources are isolated.

#### Scenario: Run unit suites in parallel without port collision

- **GIVEN** a unit-test suite opens sockets
- **WHEN** the suite runs under an opt-in parallel validation mode
- **THEN** it uses a deterministic port range assigned to that suite
- **AND** no other parallel suite uses the same range.

#### Scenario: Keep sequential validation as default

- **GIVEN** no parallel job count is requested
- **WHEN** `./scripts/validate.sh test` runs
- **THEN** the unit-test validation remains sequential and preserves the
  existing complete-suite gate.
