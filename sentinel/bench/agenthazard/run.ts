#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadDataset,
  sampleDataset,
  summarizeDataset,
} from "./adapter.js";
import { writeReportFiles } from "./report.js";
import type {
  AgentHazardCategory,
  AgentHazardJailbreakMethod,
  BenchRunArgs,
  DryRunReport,
} from "./types.js";
import {
  AGENTHAZARD_CATEGORIES,
  AGENTHAZARD_JAILBREAK_METHODS,
} from "./types.js";

const DEFAULT_DATASET = "../AgentHazard/data/dataset.json";
const DEFAULT_OUT = "results/agenthazard-p0";
const DEFAULT_SAMPLE_PER_CATEGORY = 3;
const DEFAULT_SEED = 1337;

export async function main(argv = process.argv.slice(2)): Promise<void> {
  const args = parseArgs(argv);
  if (!args.dryRun) {
    throw new Error("Only Phase 0 --dry-run is implemented. Pass --dry-run to generate the offline report.");
  }

  const datasetPath = path.resolve(args.dataset);
  const outDir = path.resolve(args.out);
  const dataset = await loadDataset(datasetPath);
  const selected = sampleDataset(dataset, {
    perCategory: args.samplePerCategory,
    seed: args.seed,
    categories: args.categories,
    jailbreakMethods: args.jailbreakMethods,
  });
  const report: DryRunReport = {
    generatedAt: new Date().toISOString(),
    datasetPath,
    options: {
      perCategory: args.samplePerCategory,
      seed: args.seed,
      categories: args.categories,
      jailbreakMethods: args.jailbreakMethods,
    },
    summary: summarizeDataset(dataset, selected),
    selected,
  };
  await writeReportFiles(report, outDir);

  console.log(`AgentHazard Phase 0 dry-run complete.`);
  console.log(`Dataset instances: ${report.summary.total}`);
  console.log(`Selected instances: ${report.summary.selected}`);
  console.log(`Output: ${outDir}`);
}

export function parseArgs(argv: string[]): BenchRunArgs {
  const args: BenchRunArgs = {
    dataset: DEFAULT_DATASET,
    out: DEFAULT_OUT,
    samplePerCategory: DEFAULT_SAMPLE_PER_CATEGORY,
    seed: DEFAULT_SEED,
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "--dataset":
        args.dataset = readValue(argv, ++i, arg);
        break;
      case "--out":
        args.out = readValue(argv, ++i, arg);
        break;
      case "--sample-per-category":
      case "--sample":
        args.samplePerCategory = readPositiveInt(readValue(argv, ++i, arg), arg);
        break;
      case "--seed":
        args.seed = readPositiveInt(readValue(argv, ++i, arg), arg);
        break;
      case "--categories":
        args.categories = parseList(readValue(argv, ++i, arg), parseCategory);
        break;
      case "--jailbreak-methods":
      case "--methods":
        args.jailbreakMethods = parseList(readValue(argv, ++i, arg), parseMethod);
        break;
      case "--dry-run":
        args.dryRun = true;
        break;
      case "--help":
      case "-h":
        printHelp();
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return args;
}

function readValue(argv: string[], index: number, flag: string): string {
  const value = argv[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function readPositiveInt(value: string, flag: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${flag} must be a positive integer, got ${value}`);
  }
  return parsed;
}

function parseList<T>(value: string, parser: (value: string) => T): T[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map(parser);
}

function parseCategory(value: string): AgentHazardCategory {
  if ((AGENTHAZARD_CATEGORIES as readonly string[]).includes(value)) {
    return value as AgentHazardCategory;
  }
  throw new Error(`Unknown category: ${value}`);
}

function parseMethod(value: string): AgentHazardJailbreakMethod {
  if ((AGENTHAZARD_JAILBREAK_METHODS as readonly string[]).includes(value)) {
    return value as AgentHazardJailbreakMethod;
  }
  throw new Error(`Unknown jailbreak method: ${value}`);
}

function printHelp(): void {
  console.log(`AgentHazard Phase 0 dry-run

Usage:
  node sentinel/bench/agenthazard/run.js --dry-run [options]

Options:
  --dataset <path>              AgentHazard dataset JSON path (default: ${DEFAULT_DATASET})
  --out <dir>                   Output directory (default: ${DEFAULT_OUT})
  --sample-per-category <n>     Selected instances per category (default: ${DEFAULT_SAMPLE_PER_CATEGORY})
  --seed <n>                    Deterministic sampling seed (default: ${DEFAULT_SEED})
  --categories <a,b>            Optional comma-separated category filter
  --jailbreak-methods <a,b>     Optional comma-separated jailbreak method filter
  --dry-run                     Generate Phase 0 report
`);
}

const isCli = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isCli) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
