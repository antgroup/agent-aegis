import { promises as fs } from "node:fs";
import path from "node:path";
import { CATEGORY_MAPPINGS } from "./mapper.js";
export async function writeReportFiles(report, outDir) {
    await fs.mkdir(outDir, { recursive: true });
    await fs.writeFile(path.join(outDir, "summary.json"), JSON.stringify({
        generatedAt: report.generatedAt,
        datasetPath: report.datasetPath,
        options: report.options,
        summary: report.summary,
    }, null, 2) + "\n", "utf8");
    await fs.writeFile(path.join(outDir, "sample.json"), JSON.stringify(report.selected, null, 2) + "\n", "utf8");
    await fs.writeFile(path.join(outDir, "report.md"), renderMarkdown(report), "utf8");
}
export function renderMarkdown(report) {
    const lines = [];
    lines.push("# AgentHazard Phase 0 Dry-Run Report");
    lines.push("");
    lines.push("## Run Metadata");
    lines.push("");
    lines.push(`- Generated at: ${report.generatedAt}`);
    lines.push(`- Dataset: \`${report.datasetPath}\``);
    lines.push(`- Seed: \`${report.options.seed}\``);
    lines.push(`- Requested sample per category: \`${report.options.perCategory}\``);
    if (report.options.categories?.length) {
        lines.push(`- Category filter: ${report.options.categories.map((c) => `\`${c}\``).join(", ")}`);
    }
    if (report.options.jailbreakMethods?.length) {
        lines.push(`- Jailbreak method filter: ${report.options.jailbreakMethods.map((m) => `\`${m}\``).join(", ")}`);
    }
    lines.push("");
    lines.push("## Dataset Summary");
    lines.push("");
    lines.push(`- Total instances: ${report.summary.total}`);
    lines.push(`- Selected instances: ${report.summary.selected}`);
    lines.push("");
    lines.push("### By Category");
    lines.push("");
    lines.push("| Category | Dataset | Selected |");
    lines.push("|---|---:|---:|");
    for (const category of Object.keys(report.summary.byCategory).sort()) {
        lines.push(`| ${category} | ${report.summary.byCategory[category] ?? 0} | ${report.summary.selectedByCategory[category] ?? 0} |`);
    }
    lines.push("");
    lines.push("### By Jailbreak Method");
    lines.push("");
    lines.push("| Jailbreak Method | Dataset | Selected |");
    lines.push("|---|---:|---:|");
    for (const method of Object.keys(report.summary.byJailbreakMethod).sort()) {
        lines.push(`| ${method} | ${report.summary.byJailbreakMethod[method] ?? 0} | ${report.summary.selectedByJailbreakMethod[method] ?? 0} |`);
    }
    lines.push("");
    lines.push("## Expected Snapshot Coverage Map");
    lines.push("");
    lines.push("| Category | Expected Signals | Snapshot Fields | Causal Chains | Known Gaps |");
    lines.push("|---|---|---|---|---|");
    for (const mapping of Object.values(CATEGORY_MAPPINGS).sort((a, b) => a.category.localeCompare(b.category))) {
        lines.push(`| ${mapping.category} | ${joinCell(mapping.expectedSignals)} | ${joinCell(mapping.expectedSnapshotFields)} | ${joinCell(mapping.expectedCausalChains)} | ${joinCell(mapping.knownGaps)} |`);
    }
    lines.push("");
    lines.push("## Selected Instances");
    lines.push("");
    lines.push("| Rank | ID | Category | Jailbreak Method | Turns | Source |");
    lines.push("|---:|---:|---|---|---:|---|");
    for (const item of report.selected) {
        lines.push(`| ${item.sampleRank} | ${item.id} | ${item.category} | ${item.jailbreak_method} | ${item.decomposed_query.length} | ${item.source || "-"} |`);
    }
    lines.push("");
    lines.push("## Next Phase Gate");
    lines.push("");
    lines.push("- Phase 0 passes when category/strategy sampling is stable and output files are reproducible for the same seed.");
    lines.push("- Phase 0.5 should add a Snapshot exporter before any Docker/eBPF collection is attempted.");
    lines.push("");
    return `${lines.join("\n")}\n`;
}
function joinCell(values) {
    return values.length > 0 ? values.map((v) => `\`${v}\``).join("<br>") : "-";
}
