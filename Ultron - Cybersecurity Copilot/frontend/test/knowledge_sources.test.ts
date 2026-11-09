import { test } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

const ROOT_DIR = path.resolve('.');

test('M14 Contract: api.ts exports all required knowledge source client functions', () => {
  const apiPath = path.join(ROOT_DIR, 'src', 'api.ts');
  const apiContent = fs.readFileSync(apiPath, 'utf8');

  assert.ok(apiContent.includes('export async function listKnowledgeSources'), 'api.ts must export listKnowledgeSources');
  assert.ok(apiContent.includes('export async function getKnowledgeSource'), 'api.ts must export getKnowledgeSource');
  assert.ok(apiContent.includes('export async function importLocalKnowledgeSource'), 'api.ts must export importLocalKnowledgeSource');
  assert.ok(apiContent.includes('export async function uploadKnowledgeSource'), 'api.ts must export uploadKnowledgeSource');
  assert.ok(apiContent.includes('export async function ingestKnowledgeText'), 'api.ts must export ingestKnowledgeText');
  assert.ok(apiContent.includes('export async function deactivateKnowledgeSource'), 'api.ts must export deactivateKnowledgeSource');
  assert.ok(apiContent.includes('export async function retryKnowledgeSource'), 'api.ts must export retryKnowledgeSource');
});

test('M14 Contract: types.ts defines KnowledgeSource, KnowledgeChunk, and AuthorityLevel', () => {
  const typesPath = path.join(ROOT_DIR, 'src', 'types.ts');
  const typesContent = fs.readFileSync(typesPath, 'utf8');

  assert.ok(typesContent.includes('export interface KnowledgeSource'), 'types.ts must define KnowledgeSource interface');
  assert.ok(typesContent.includes('export interface KnowledgeChunk'), 'types.ts must define KnowledgeChunk interface');
  assert.ok(typesContent.includes('export type KnowledgeAuthorityLevel'), 'types.ts must define KnowledgeAuthorityLevel');
  assert.ok(typesContent.includes('STANDARD'), 'types.ts must include STANDARD authority');
  assert.ok(typesContent.includes('VENDOR_OFFICIAL'), 'types.ts must include VENDOR_OFFICIAL authority');
});

test('M14 UI: MemoryKnowledgeTab implements Knowledge Corpus tab and intake modal', () => {
  const tabPath = path.join(ROOT_DIR, 'src', 'components', 'workspace', 'tabs', 'MemoryKnowledgeTab.tsx');
  const tabContent = fs.readFileSync(tabPath, 'utf8');

  // Verify dual sub-views
  assert.ok(tabContent.includes('Knowledge Corpus (M14)'), 'Must include Knowledge Corpus tab switcher');
  assert.ok(tabContent.includes('Assessment Memory Tiers (M12)'), 'Must include Assessment Memory Tiers switcher');

  // Verify 3 intake modes
  assert.ok(tabContent.includes('Upload File (PDF / MD / TXT)'), 'Must support File Upload mode');
  assert.ok(tabContent.includes('Direct Markdown / Text'), 'Must support Direct Text mode');
  assert.ok(tabContent.includes('Local Imports Dir'), 'Must support Local Directory Import mode');

  // Verify accessibility
  assert.ok(tabContent.includes('role="dialog"'), 'Intake modal must have role="dialog"');
  assert.ok(tabContent.includes('aria-modal="true"'), 'Intake modal must have aria-modal="true"');

  // Verify security containment guidance
  assert.ok(tabContent.includes('data/knowledge/imports/'), 'Must reference secure data/knowledge/imports/ containment');
});

test('Stage C Contract: api.ts and types.ts define distinct graph extraction models and client functions', () => {
  const apiPath = path.join(ROOT_DIR, 'src', 'api.ts');
  const apiContent = fs.readFileSync(apiPath, 'utf8');

  assert.ok(apiContent.includes('export async function extractKnowledgeGraph'), 'api.ts must export extractKnowledgeGraph');
  assert.ok(apiContent.includes('export async function getKnowledgeGraphStatus'), 'api.ts must export getKnowledgeGraphStatus');
  assert.ok(apiContent.includes('export async function getKnowledgeGraphStats'), 'api.ts must export getKnowledgeGraphStats');

  const typesPath = path.join(ROOT_DIR, 'src', 'types.ts');
  const typesContent = fs.readFileSync(typesPath, 'utf8');

  assert.ok(typesContent.includes('export interface GraphExtractionResponse'), 'types.ts must define GraphExtractionResponse');
  assert.ok(typesContent.includes('export interface SourceGraphStatusResponse'), 'types.ts must define SourceGraphStatusResponse');
  assert.ok(typesContent.includes('export interface KnowledgeGraphStatsResponse'), 'types.ts must define KnowledgeGraphStatsResponse');
  assert.ok(typesContent.includes('status: \'COMPLETED\' | \'FAILED\' | \'EMPTY\''), 'Graph extraction status must model COMPLETED, FAILED, EMPTY');
});

test('Stage E Contract: api.ts and types.ts define graph integrity audit models and client functions', () => {
  const apiPath = path.join(ROOT_DIR, 'src', 'api.ts');
  const apiContent = fs.readFileSync(apiPath, 'utf8');

  assert.ok(apiContent.includes('export async function auditKnowledgeGraph'), 'api.ts must export auditKnowledgeGraph');

  const typesPath = path.join(ROOT_DIR, 'src', 'types.ts');
  const typesContent = fs.readFileSync(typesPath, 'utf8');

  assert.ok(typesContent.includes('export interface GraphIntegrityIssue'), 'types.ts must define GraphIntegrityIssue');
  assert.ok(typesContent.includes('export interface GraphAuditSummary'), 'types.ts must define GraphAuditSummary');
  assert.ok(typesContent.includes('export interface GraphAuditResponse'), 'types.ts must define GraphAuditResponse');
  assert.ok(typesContent.includes('read_only_guarantee: boolean'), 'GraphAuditResponse must include read_only_guarantee');

  const tabPath = path.join(ROOT_DIR, 'src', 'components', 'workspace', 'tabs', 'MemoryKnowledgeTab.tsx');
  const tabContent = fs.readFileSync(tabPath, 'utf8');
  assert.ok(tabContent.includes('Audit Graph Integrity'), 'MemoryKnowledgeTab must include Audit Graph Integrity action');
  assert.ok(tabContent.includes('PRAGMA query_only = ON'), 'MemoryKnowledgeTab must note read-only guarantee');
});


