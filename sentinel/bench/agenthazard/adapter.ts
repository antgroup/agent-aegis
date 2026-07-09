import { promises as fs } from "node:fs";
import type {
  AgentHazardCategory,
  AgentHazardInstance,
  AgentHazardJailbreakMethod,
  DatasetSummary,
  SampledInstance,
  SamplingOptions,
} from "./types.js";
import {
  AGENTHAZARD_CATEGORIES,
  AGENTHAZARD_JAILBREAK_METHODS,
} from "./types.js";

const CATEGORY_SET = new Set<string>(AGENTHAZARD_CATEGORIES);
const METHOD_SET = new Set<string>(AGENTHAZARD_JAILBREAK_METHODS);

export async function loadDataset(datasetPath: string): Promise<AgentHazardInstance[]> {
  const raw = JSON.parse(await fs.readFile(datasetPath, "utf8")) as unknown;
  if (!Array.isArray(raw)) {
    throw new Error(`AgentHazard dataset must be a JSON array: ${datasetPath}`);
  }
  return raw.map((item, index) => parseInstance(item, index));
}

export function sampleDataset(
  dataset: AgentHazardInstance[],
  opts: SamplingOptions,
): SampledInstance[] {
  if (!Number.isInteger(opts.perCategory) || opts.perCategory <= 0) {
    throw new Error(`perCategory must be a positive integer, got ${opts.perCategory}`);
  }
  const categoryFilter = opts.categories ? new Set(opts.categories) : undefined;
  const methodFilter = opts.jailbreakMethods ? new Set(opts.jailbreakMethods) : undefined;
  const filtered = dataset.filter((item) => {
    if (categoryFilter && !categoryFilter.has(item.category)) return false;
    if (methodFilter && !methodFilter.has(item.jailbreak_method)) return false;
    return true;
  });

  const byCategory = groupBy(filtered, (item) => item.category);
  const selected: SampledInstance[] = [];
  for (const category of sortedKeys(byCategory)) {
    const categoryItems = byCategory[category] ?? [];
    selected.push(...sampleCategory(categoryItems, opts.perCategory, opts.seed));
  }
  return selected
    .sort((a, b) => a.category.localeCompare(b.category) || a.sampleRank - b.sampleRank || a.id - b.id)
    .map((item, idx) => ({ ...item, sampleRank: idx + 1 }));
}

export function summarizeDataset(
  dataset: AgentHazardInstance[],
  selected: SampledInstance[],
): DatasetSummary {
  return {
    total: dataset.length,
    selected: selected.length,
    byCategory: countBy(dataset, (item) => item.category),
    byJailbreakMethod: countBy(dataset, (item) => item.jailbreak_method),
    byStratum: countBy(dataset, (item) => stratumKey(item)),
    selectedByCategory: countBy(selected, (item) => item.category),
    selectedByJailbreakMethod: countBy(selected, (item) => item.jailbreak_method),
    selectedByStratum: countBy(selected, (item) => item.stratumKey),
  };
}

function sampleCategory(
  items: AgentHazardInstance[],
  perCategory: number,
  seed: number,
): SampledInstance[] {
  const strata = groupBy(items, (item) => item.jailbreak_method);
  const selected: AgentHazardInstance[] = [];
  const category = items[0]?.category ?? "category";
  const methodKeys = deterministicShuffle(sortedKeys(strata), seedFor(seed, category));

  for (const method of methodKeys) {
    const bucket = deterministicShuffle(strata[method] ?? [], seedFor(seed, method));
    const first = bucket[0];
    if (first) selected.push(first);
    if (selected.length >= perCategory) break;
  }

  if (selected.length < perCategory) {
    const selectedIds = new Set(selected.map((item) => item.id));
    const remainder = deterministicShuffle(
      items.filter((item) => !selectedIds.has(item.id)),
      seedFor(seed, category),
    );
    for (const item of remainder) {
      selected.push(item);
      if (selected.length >= perCategory) break;
    }
  }

  return selected.slice(0, perCategory).map((item, index) => ({
    ...item,
    sampleRank: index + 1,
    stratumKey: stratumKey(item),
  }));
}

function parseInstance(raw: unknown, index: number): AgentHazardInstance {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`dataset[${index}] must be an object`);
  }
  const r = raw as Record<string, unknown>;
  const id = readNumber(r.id, `dataset[${index}].id`);
  const category = readCategory(r.category, `dataset[${index}].category`);
  const jailbreakMethod = readMethod(r.jailbreak_method, `dataset[${index}].jailbreak_method`);
  const query = readString(r.query, `dataset[${index}].query`);
  const decomposedQuery = readStringArray(r.decomposed_query, `dataset[${index}].decomposed_query`);
  const comment = typeof r.comment === "string" ? r.comment : "";
  const source = typeof r.source === "string" ? r.source : "";
  const originalId = typeof r.original_id === "number" ? r.original_id : undefined;
  return {
    id,
    category,
    jailbreak_method: jailbreakMethod,
    query,
    decomposed_query: decomposedQuery,
    comment,
    source,
    original_id: originalId,
  };
}

function readNumber(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${field} must be a finite number`);
  }
  return value;
}

function readString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`${field} must be a string`);
  }
  return value;
}

function readStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`${field} must be a string array`);
  }
  return value as string[];
}

function readCategory(value: unknown, field: string): AgentHazardCategory {
  if (typeof value !== "string" || !CATEGORY_SET.has(value)) {
    throw new Error(`${field} has unknown category: ${String(value)}`);
  }
  return value as AgentHazardCategory;
}

function readMethod(value: unknown, field: string): AgentHazardJailbreakMethod {
  if (typeof value !== "string" || !METHOD_SET.has(value)) {
    throw new Error(`${field} has unknown jailbreak method: ${String(value)}`);
  }
  return value as AgentHazardJailbreakMethod;
}

function stratumKey(item: Pick<AgentHazardInstance, "category" | "jailbreak_method">): string {
  return `${item.category}/${item.jailbreak_method}`;
}

function groupBy<T>(
  items: T[],
  keyFn: (item: T) => string,
): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const item of items) {
    const key = keyFn(item);
    (out[key] ??= []).push(item);
  }
  return out;
}

function countBy<T>(items: T[], keyFn: (item: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of items) {
    const key = keyFn(item);
    out[key] = (out[key] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(out).sort(([a], [b]) => a.localeCompare(b)));
}

function sortedKeys<T>(record: Record<string, T>): string[] {
  return Object.keys(record).sort((a, b) => a.localeCompare(b));
}

function deterministicShuffle<T>(items: T[], seed: number): T[] {
  const out = [...items];
  let state = seed >>> 0;
  for (let i = out.length - 1; i > 0; i--) {
    state = xorshift32(state);
    const j = state % (i + 1);
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

function xorshift32(input: number): number {
  let x = input || 0x9e3779b9;
  x ^= x << 13;
  x ^= x >>> 17;
  x ^= x << 5;
  return x >>> 0;
}

function seedFor(seed: number, text: string): number {
  let out = seed >>> 0;
  for (let i = 0; i < text.length; i++) {
    out = xorshift32(out ^ text.charCodeAt(i));
  }
  return out;
}
