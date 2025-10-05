#!/usr/bin/env node

import { Command } from "commander";
import AuditSumary from "./AuditSummary";

main();

async function main() {
    const cli = new Command();

    const packageJson = require("../package.json");

    cli
        .name(packageJson.name)
        .version(packageJson.version)
        .description("Displays vulnerability summary for your NPM packages")
        .option("-i, --init", "creates a default .audit-summary.json file")
        .option("-v, --verbose", "shows extra information")
        .option("-j, --json", "output results in JSON format")
        .option("-w, --workspace <name>", "when using an NPM workspace")
        .parse(process.argv);

    const withOptions = cli.opts();

    const auditSummary = new AuditSumary(withOptions, packageJson.name);

    auditSummary.executeAudit();

    // await gitEnvironmentBranches.executeCheck();
}