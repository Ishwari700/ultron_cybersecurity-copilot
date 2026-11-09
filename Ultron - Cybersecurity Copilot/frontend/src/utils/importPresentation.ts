import type { IngestionResult } from '../types';

export type ImportResultStatus =
  | 'ALL_NEW'
  | 'ALL_DUPLICATE'
  | 'ALL_OUT_OF_SCOPE'
  | 'ALL_PARSE_FAILURES'
  | 'MIXED'
  | 'EMPTY';

export interface ImportPresentation {
  status: ImportResultStatus;
  headline: string;
  submessage: string;
  isAllDuplicates: boolean;
  isAllNew: boolean;
  isAllOutOfScope: boolean;
  isAllParseFailures: boolean;
  badgeType: 'success' | 'info' | 'warning' | 'error';
  counts: {
    added: number;
    duplicates: number;
    outOfScope: number;
    parseFailures: number;
    redactedSecrets: number;
    totalImported: number;
  };
  details: {
    outOfScopeList: Array<{ transaction?: number; host?: string; reason?: string }>;
    parseErrorsList: string[];
  };
}

/**
 * Derives a structured, human-centric presentation model from an IngestionResult.
 *
 * Distinguishes:
 * 1. All duplicates (re-import of existing data) -> informative "already present" notice, NOT an error or out-of-scope.
 * 2. All new observations -> success message.
 * 3. Mixed import -> explicit separate line items for added, duplicates, out-of-scope, and parse failures.
 * 4. Only out-of-scope -> clear scope exclusion message specifying the target host boundary.
 * 5. Parse failures -> dedicated syntax error report.
 */
export function getImportPresentation(
  result: IngestionResult | null | undefined,
  targetHost: string = ''
): ImportPresentation {
  if (!result) {
    return {
      status: 'EMPTY',
      headline: 'No Traffic Imported',
      submessage: 'No import data available.',
      isAllDuplicates: false,
      isAllNew: false,
      isAllOutOfScope: false,
      isAllParseFailures: false,
      badgeType: 'info',
      counts: {
        added: 0,
        duplicates: 0,
        outOfScope: 0,
        parseFailures: 0,
        redactedSecrets: 0,
        totalImported: 0,
      },
      details: {
        outOfScopeList: [],
        parseErrorsList: [],
      },
    };
  }

  const added = result.observations_added ?? result.accepted_count ?? 0;
  const duplicates = result.duplicates ?? result.duplicate_count ?? 0;
  const outOfScope = result.out_of_scope_count ?? (result.out_of_scope?.length || 0);
  const parseFailures = result.parsing_failures ?? (result.parse_errors?.length || (result.errors?.length || 0));
  const redactedSecrets = result.redacted_secret_count ?? 0;
  const totalImported = result.imported_count || (added + duplicates + outOfScope + parseFailures);

  const isAllDuplicates = added === 0 && duplicates > 0 && outOfScope === 0 && parseFailures === 0;
  const isAllNew = added > 0 && duplicates === 0 && outOfScope === 0 && parseFailures === 0;
  const isAllOutOfScope = added === 0 && duplicates === 0 && outOfScope > 0 && parseFailures === 0;
  const isAllParseFailures = added === 0 && duplicates === 0 && outOfScope === 0 && parseFailures > 0;

  let status: ImportResultStatus = 'MIXED';
  let headline = 'Import Complete';
  let submessage = '';
  let badgeType: 'success' | 'info' | 'warning' | 'error' = 'info';

  if (isAllDuplicates) {
    status = 'ALL_DUPLICATE';
    headline = 'All Transactions Already Present';
    submessage = 'All imported transactions were already present. No new observations were created.';
    badgeType = 'info';
  } else if (isAllNew) {
    status = 'ALL_NEW';
    headline = 'Import Successful';
    submessage = `Successfully added ${added} new observation${added === 1 ? '' : 's'} to investigation evidence.`;
    badgeType = 'success';
  } else if (isAllOutOfScope) {
    status = 'ALL_OUT_OF_SCOPE';
    headline = 'Traffic Excluded — Out of Scope';
    const scopeTargetDesc = targetHost ? ` (target: ${targetHost})` : '';
    submessage = `All ${outOfScope} captured transaction${outOfScope === 1 ? '' : 's'} targeted destinations outside the investigation scope${scopeTargetDesc}.`;
    badgeType = 'warning';
  } else if (isAllParseFailures) {
    status = 'ALL_PARSE_FAILURES';
    headline = 'Import Failed — Parsing Error';
    submessage = `Failed to parse ${parseFailures} transaction${parseFailures === 1 ? '' : 's'} due to invalid HTTP syntax.`;
    badgeType = 'error';
  } else if (added === 0 && duplicates === 0 && outOfScope === 0 && parseFailures === 0) {
    status = 'EMPTY';
    headline = 'No Transactions Processed';
    submessage = 'The input contained no HTTP transactions.';
    badgeType = 'info';
  } else {
    // Mixed import
    status = 'MIXED';
    headline = 'Import Complete';
    const parts: string[] = [];
    if (added > 0) parts.push(`${added} new observation${added === 1 ? '' : 's'}`);
    if (duplicates > 0) parts.push(`${duplicates} duplicate${duplicates === 1 ? '' : 's'} skipped`);
    if (outOfScope > 0) parts.push(`${outOfScope} out-of-scope excluded`);
    if (parseFailures > 0) parts.push(`${parseFailures} parse failure${parseFailures === 1 ? '' : 's'}`);
    submessage = parts.join(' · ');
    badgeType = added > 0 ? 'success' : (outOfScope > 0 ? 'warning' : 'info');
  }

  const outOfScopeList = result.out_of_scope || [];
  const parseErrorsList = result.parse_errors || result.errors || [];

  return {
    status,
    headline,
    submessage,
    isAllDuplicates,
    isAllNew,
    isAllOutOfScope,
    isAllParseFailures,
    badgeType,
    counts: {
      added,
      duplicates,
      outOfScope,
      parseFailures,
      redactedSecrets,
      totalImported,
    },
    details: {
      outOfScopeList,
      parseErrorsList,
    },
  };
}
