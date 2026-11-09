import test from 'node:test';
import assert from 'node:assert/strict';
import { getImportPresentation } from '../src/utils/importPresentation.ts';
import type { IngestionResult } from '../src/types.ts';

test('Scenario A: 16 new transactions -> 16 observations added', () => {
  const result: IngestionResult = {
    imported_count: 16,
    accepted_count: 16,
    duplicate_count: 0,
    out_of_scope_count: 0,
    redacted_secret_count: 32,
    parsing_failures: 0,
    errors: [],
    accepted_observations: [],
    observations_added: 16,
    duplicates: 0,
    out_of_scope: [],
    parse_errors: [],
  };

  const presentation = getImportPresentation(result, 'lab.target.local');

  assert.equal(presentation.status, 'ALL_NEW');
  assert.equal(presentation.isAllNew, true);
  assert.equal(presentation.isAllDuplicates, false);
  assert.equal(presentation.isAllOutOfScope, false);
  assert.equal(presentation.isAllParseFailures, false);
  assert.equal(presentation.badgeType, 'success');
  assert.equal(presentation.counts.added, 16);
  assert.equal(presentation.counts.duplicates, 0);
  assert.equal(presentation.counts.outOfScope, 0);
  assert.equal(presentation.counts.parseFailures, 0);
  assert.equal(presentation.counts.redactedSecrets, 32);
  assert.equal(presentation.headline, 'Import Successful');
  assert.ok(presentation.submessage.includes('16 new observations'));
});

test('Scenario B: Same 16 transactions imported again -> 0 observations added, 16 duplicates', () => {
  const result: IngestionResult = {
    imported_count: 16,
    accepted_count: 0,
    duplicate_count: 16,
    out_of_scope_count: 0,
    redacted_secret_count: 35,
    parsing_failures: 0,
    errors: [],
    accepted_observations: [],
    observations_added: 0,
    duplicates: 16,
    out_of_scope: [],
    parse_errors: [],
  };

  const presentation = getImportPresentation(result, 'lab.target.local');

  assert.equal(presentation.status, 'ALL_DUPLICATE');
  assert.equal(presentation.isAllDuplicates, true);
  assert.equal(presentation.isAllNew, false);
  assert.equal(presentation.isAllOutOfScope, false);
  assert.equal(presentation.isAllParseFailures, false);
  assert.equal(presentation.badgeType, 'info');
  assert.equal(presentation.counts.added, 0);
  assert.equal(presentation.counts.duplicates, 16);
  assert.equal(presentation.counts.outOfScope, 0);
  assert.equal(presentation.counts.parseFailures, 0);
  assert.equal(presentation.counts.redactedSecrets, 35);
  assert.equal(presentation.headline, 'All Transactions Already Present');
  assert.equal(
    presentation.submessage,
    'All imported transactions were already present. No new observations were created.'
  );
  // Ensure duplicates are not described as out-of-scope or errors
  assert.equal(presentation.details.outOfScopeList.length, 0);
  assert.equal(presentation.details.parseErrorsList.length, 0);
});

test('Scenario C: Mixed import -> new + duplicate + out-of-scope counts displayed separately', () => {
  const result: IngestionResult = {
    imported_count: 20,
    accepted_count: 10,
    duplicate_count: 5,
    out_of_scope_count: 3,
    redacted_secret_count: 12,
    parsing_failures: 2,
    errors: ['Syntax error in transaction 19'],
    accepted_observations: [],
    observations_added: 10,
    duplicates: 5,
    out_of_scope: [
      { transaction: 11, host: 'attacker.com', reason: 'Destination host does not match target scope' },
      { transaction: 12, host: 'evil.corp', reason: 'Destination host does not match target scope' },
      { transaction: 13, host: 'thirdparty.net', reason: 'Destination host does not match target scope' },
    ],
    parse_errors: ['Syntax error in transaction 19', 'Malformed chunk in transaction 20'],
  };

  const presentation = getImportPresentation(result, 'api.target.local');

  assert.equal(presentation.status, 'MIXED');
  assert.equal(presentation.isAllDuplicates, false);
  assert.equal(presentation.isAllNew, false);
  assert.equal(presentation.isAllOutOfScope, false);
  assert.equal(presentation.isAllParseFailures, false);
  assert.equal(presentation.counts.added, 10);
  assert.equal(presentation.counts.duplicates, 5);
  assert.equal(presentation.counts.outOfScope, 3);
  assert.equal(presentation.counts.parseFailures, 2);
  assert.equal(presentation.counts.redactedSecrets, 12);
  assert.equal(presentation.counts.totalImported, 20);

  // Submessage contains distinct descriptions for each category
  assert.ok(presentation.submessage.includes('10 new observations'));
  assert.ok(presentation.submessage.includes('5 duplicates skipped'));
  assert.ok(presentation.submessage.includes('3 out-of-scope excluded'));
  assert.ok(presentation.submessage.includes('2 parse failures'));

  // Separate audit arrays
  assert.equal(presentation.details.outOfScopeList.length, 3);
  assert.equal(presentation.details.outOfScopeList[0].host, 'attacker.com');
  assert.equal(presentation.details.parseErrorsList.length, 2);
});

test('Scenario D: Import containing only genuinely out-of-scope traffic -> clearly shown as out-of-scope, not duplicate', () => {
  const result: IngestionResult = {
    imported_count: 4,
    accepted_count: 0,
    duplicate_count: 0,
    out_of_scope_count: 4,
    redacted_secret_count: 0,
    parsing_failures: 0,
    errors: [],
    accepted_observations: [],
    observations_added: 0,
    duplicates: 0,
    out_of_scope: [
      { transaction: 1, host: 'external.service.com', reason: 'Outside target scope' },
      { transaction: 2, host: 'external.service.com', reason: 'Outside target scope' },
      { transaction: 3, host: 'external.service.com', reason: 'Outside target scope' },
      { transaction: 4, host: 'external.service.com', reason: 'Outside target scope' },
    ],
    parse_errors: [],
  };

  const presentation = getImportPresentation(result, 'api.target.local');

  assert.equal(presentation.status, 'ALL_OUT_OF_SCOPE');
  assert.equal(presentation.isAllOutOfScope, true);
  assert.equal(presentation.isAllDuplicates, false);
  assert.equal(presentation.isAllNew, false);
  assert.equal(presentation.isAllParseFailures, false);
  assert.equal(presentation.badgeType, 'warning');
  assert.equal(presentation.counts.added, 0);
  assert.equal(presentation.counts.duplicates, 0);
  assert.equal(presentation.counts.outOfScope, 4);
  assert.equal(presentation.counts.parseFailures, 0);
  assert.equal(presentation.headline, 'Traffic Excluded — Out of Scope');
  assert.ok(presentation.submessage.includes('outside the investigation scope (target: api.target.local)'));
  assert.equal(presentation.details.outOfScopeList.length, 4);
});

test('Scenario E: Parse failures -> clearly shown separately', () => {
  const result: IngestionResult = {
    imported_count: 2,
    accepted_count: 0,
    duplicate_count: 0,
    out_of_scope_count: 0,
    redacted_secret_count: 0,
    parsing_failures: 2,
    errors: ['Line 1: Invalid HTTP request line', 'Line 45: Header contains invalid CRLF sequence'],
    accepted_observations: [],
    observations_added: 0,
    duplicates: 0,
    out_of_scope: [],
    parse_errors: ['Line 1: Invalid HTTP request line', 'Line 45: Header contains invalid CRLF sequence'],
  };

  const presentation = getImportPresentation(result, 'api.target.local');

  assert.equal(presentation.status, 'ALL_PARSE_FAILURES');
  assert.equal(presentation.isAllParseFailures, true);
  assert.equal(presentation.isAllDuplicates, false);
  assert.equal(presentation.isAllNew, false);
  assert.equal(presentation.isAllOutOfScope, false);
  assert.equal(presentation.badgeType, 'error');
  assert.equal(presentation.counts.added, 0);
  assert.equal(presentation.counts.duplicates, 0);
  assert.equal(presentation.counts.outOfScope, 0);
  assert.equal(presentation.counts.parseFailures, 2);
  assert.equal(presentation.headline, 'Import Failed — Parsing Error');
  assert.ok(presentation.submessage.includes('Failed to parse 2 transactions due to invalid HTTP syntax'));
  assert.equal(presentation.details.parseErrorsList.length, 2);
});
