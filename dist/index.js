#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const AuditSummary_1 = __importDefault(require("./AuditSummary"));
main();
async function main() {
    const cli = new commander_1.Command();
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
    const auditSummary = new AuditSummary_1.default(withOptions, packageJson.name);
    auditSummary.executeAudit();
    // await gitEnvironmentBranches.executeCheck();
}
