"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_child_process_1 = require("node:child_process");
const ascii_table3_1 = require("ascii-table3");
const chalk_1 = __importDefault(require("chalk"));
const fs = __importStar(require("node:fs"));
const path = __importStar(require("node:path"));
const SEV_ORDER = {
    critical: 4,
    high: 3,
    moderate: 2,
    low: 1,
    info: 0
};
const SEV_KEYS = ['critical', 'high', 'moderate', 'low', 'info'];
class AuditSumary {
    options;
    packageName;
    constructor(options, packageName) {
        this.options = options;
        this.packageName = packageName;
    }
    executeAudit() {
        // Handle init flag
        if (this.options.init) {
            this.initConfigFile();
            return;
        }
        const jsonMode = this.options.json ?? false;
        const wsIdx = this.options.workspace;
        const audit = this.getAudit();
        const tree = this.getDependencyTree();
        const rootsMap = this.buildRequiredByRootsMap(tree);
        const vulnerabilityList = this.getVulnerabilityList(audit, jsonMode);
        if (vulnerabilityList) {
            const byRoot = this.getVulnerabilitiesByRoot(vulnerabilityList, rootsMap);
            const perRootCounts = this.getVulnerabilitiesPerRootCount(byRoot);
            // Global totals
            const global = SEV_KEYS.reduce((acc, k) => ((acc[k] = 0), acc), {});
            for (const { counts } of perRootCounts.values()) {
                for (const k of SEV_KEYS)
                    global[k] += counts[k];
            }
            const globalTotal = SEV_KEYS.reduce((acc, k) => acc + global[k], 0);
            const globalCounts = {
                ...global,
                total: globalTotal
            };
            // Fetch latest versions for root packages
            const rootPackages = Array.from(byRoot.keys());
            const latestVersions = this.getLatestVersions(rootPackages);
            // Output
            if (jsonMode) {
                this.outputJSON(perRootCounts, globalCounts, tree, latestVersions);
            }
            else {
                this.outputTerminal(byRoot, perRootCounts, globalCounts, tree, latestVersions);
                // Check thresholds if config file exists
                this.checkThresholds(perRootCounts);
            }
        }
    }
    outputTerminal(byRoot, perRootCounts, globalCounts, tree, latestVersions) {
        const verbose = this.options.verbose ?? false;
        const sortedRoots = Array.from(byRoot.keys()).sort((a, b) => a.localeCompare(b));
        // Extract versions for root packages
        const rootVersions = new Map();
        const topLevel = tree.dependencies ?? {};
        for (const [topName, topNode] of Object.entries(topLevel)) {
            rootVersions.set(topName, topNode?.version ?? 'unknown');
        }
        function coloredSeverity(severity) {
            switch (SEV_ORDER[severity]) {
                case 4:
                    return chalk_1.default.magentaBright.bold(severity);
                case 3:
                    return chalk_1.default.redBright.bold(severity);
                case 2:
                    return chalk_1.default.yellowBright.bold(severity);
                default:
                    return severity;
            }
        }
        if (verbose) {
            for (const root of sortedRoots) {
                const record = perRootCounts.get(root);
                if (!record)
                    continue;
                // Sort by severity desc then name
                record.vulns.sort((a, b) => {
                    const sa = SEV_ORDER[a.severity];
                    const sb = SEV_ORDER[b.severity];
                    if (sb !== sa)
                        return sb - sa;
                    return a.name.localeCompare(b.name);
                });
                const currentVersion = rootVersions.get(root);
                const latestVersion = latestVersions.get(root);
                const versionInfo = currentVersion && latestVersion ? `${currentVersion} → latest: ${latestVersion}` : currentVersion ? currentVersion : '';
                const rootDisplay = versionInfo ? `${root} (${versionInfo})` : root;
                console.log(rootDisplay);
                for (const v of record.vulns) {
                    console.log(`  - ${v.name} [${coloredSeverity(v.severity)}] (affected: ${v.range ?? 'n/a'})`);
                }
                const summaryParts = SEV_KEYS.filter((k) => record.counts[k] > 0).map((k) => `${record.counts[k]} ${k}`);
                console.log(`  Summary: ${summaryParts.join(', ') || '0'}`);
                console.log('-----');
            }
        }
        // Global summary table
        // const rootsByTotalDesc = Array.from(perRootCounts.entries()).sort(
        //     (a, b) => b[1].counts.total - a[1].counts.total || a[0].localeCompare(b[0])
        // );
        const rootsByTotalDesc = this.sortRootsBySeverity(perRootCounts);
        const rowArrays = [];
        rowArrays.push(...this.getAllRootsRowData(rootsByTotalDesc, rootVersions, latestVersions));
        rowArrays.push(['', '', '', '', '', '', '', '', '']);
        const footer = [
            chalk_1.default.bold('TOTAL'),
            '',
            '',
            chalk_1.default.magentaBright.bold(globalCounts.critical),
            chalk_1.default.redBright.bold(globalCounts.high),
            chalk_1.default.yellowBright.bold(globalCounts.moderate),
            chalk_1.default.bold(globalCounts.low),
            chalk_1.default.bold(globalCounts.info),
            chalk_1.default.bold(globalCounts.total)
        ];
        rowArrays.push(footer);
        const table = new ascii_table3_1.AsciiTable3('NPM Packages Audit Summary (deduped by package per root dependency)')
            .setHeading('Root Dependency', 'Current', 'Latest', 'Critical', 'High', 'Moderate', 'Low', 'Info', 'Total')
            .setStyle('unicode-round')
            .setAlignRight(4)
            .setAlignRight(5)
            .setAlignRight(6)
            .setAlignRight(7)
            .setAlignRight(8)
            .setAlignRight(9)
            .addRowMatrix(rowArrays);
        console.log();
        console.log(table.toString());
    }
    getAllRootsRowData(rootsByTotalDesc, rootVersions, latestVersions) {
        const rowArrays = [];
        for (const [root, { counts }] of rootsByTotalDesc) {
            const coloredRoot = counts.critical
                ? chalk_1.default.magentaBright.bold(root)
                : counts.high
                    ? chalk_1.default.redBright.bold(root)
                    : counts.moderate
                        ? chalk_1.default.yellowBright.bold(root)
                        : root;
            const currentVersion = rootVersions.get(root) ?? '';
            const latestVersion = latestVersions.get(root) ?? '';
            const data = [
                coloredRoot,
                currentVersion,
                latestVersion,
                counts.critical ? chalk_1.default.magentaBright.bold(counts.critical) : '',
                counts.high ? chalk_1.default.redBright.bold(counts.high) : '',
                counts.moderate ? chalk_1.default.yellowBright.bold(counts.moderate) : '',
                counts.low || '',
                counts.info || '',
                counts.total || ''
            ];
            rowArrays.push(data);
        }
        return rowArrays;
    }
    /**
     * Machine-readable output
     *
     * @param perRootCounts
     * @param globalCounts
     * @param tree
     * @param latestVersions
     * @returns
     */
    outputJSON(perRootCounts, globalCounts, tree, latestVersions) {
        // Extract versions for root packages
        const rootVersions = new Map();
        const topLevel = tree.dependencies ?? {};
        for (const [topName, topNode] of Object.entries(topLevel)) {
            rootVersions.set(topName, topNode?.version ?? 'unknown');
        }
        const rootsJson = Object.fromEntries(Array.from(perRootCounts.entries()).map(([root, { vulns, counts }]) => [
            root,
            {
                currentVersion: rootVersions.get(root) ?? 'unknown',
                latestVersion: latestVersions.get(root) ?? 'unknown',
                vulnerabilities: vulns,
                summary: counts
            }
        ]));
        const out = { roots: rootsJson, global: globalCounts };
        console.log(JSON.stringify(out, null, 2));
        return;
    }
    sortRootsBySeverity(perRootCounts) {
        // Define the priority order explicitly to avoid relying on object key order.
        const severityOrder = ['critical', 'high', 'moderate', 'low', 'info'];
        return Array.from(perRootCounts.entries()).sort((a, b) => {
            const aCounts = a[1].counts;
            const bCounts = b[1].counts;
            // Compare each severity dimension in order
            for (const sev of severityOrder) {
                const diff = bCounts[sev] - aCounts[sev];
                if (diff !== 0)
                    return diff;
            }
            // Optional: fallback to total if you still want that as a differentiator
            const totalDiff = bCounts.total - aCounts.total;
            if (totalDiff !== 0)
                return totalDiff;
            // Final stable tie-breaker: alphabetical by package/root name
            return a[0].localeCompare(b[0]);
        });
    }
    /**
     * Build per-root deduped lists & counts
     */
    getVulnerabilitiesPerRootCount(vulnerabilitiesByRoot) {
        const perRootCounts = new Map();
        for (const [root, list] of vulnerabilitiesByRoot.entries()) {
            // Deduplicate by vulnerable package name per root
            const dedup = Array.from(new Map(list.map((x) => [x.name, x])).values());
            // Counts
            const counts = SEV_KEYS.reduce((acc, k) => ((acc[k] = 0), acc), {});
            for (const v of dedup)
                counts[v.severity]++;
            const total = SEV_KEYS.reduce((acc, k) => acc + counts[k], 0);
            perRootCounts.set(root, {
                vulns: dedup,
                counts: { ...counts, total }
            });
        }
        return perRootCounts;
    }
    /**
     * Build: root -> list of vulnerabilities (later dedup per root)
     * @param vulnerabilityList
     */
    getVulnerabilitiesByRoot(vulnerabilityList, rootsMap) {
        const byRoot = new Map();
        for (const v of vulnerabilityList) {
            const severity = this.normSeverity(v.severity);
            const roots = Array.from(rootsMap.get(v.name) ?? []);
            const targetRoots = roots.length ? roots : ['(unresolved root)'];
            for (const r of targetRoots) {
                const arr = byRoot.get(r) ?? [];
                arr.push({ name: v.name, severity, range: v.range });
                byRoot.set(r, arr);
            }
        }
        return byRoot;
    }
    getVulnerabilityList(audit, jsonMode) {
        const vulnList = Object.values(audit.vulnerabilities ?? {});
        if (vulnList.length === 0) {
            if (jsonMode) {
                // Emit empty structure for consistency
                const emptyCounts = {
                    critical: 0,
                    high: 0,
                    moderate: 0,
                    low: 0,
                    info: 0,
                    total: 0
                };
                console.info(JSON.stringify({ roots: {}, global: emptyCounts }, null, 2));
            }
            else {
                console.info('No vulnerabilities found.');
            }
            return;
        }
        return vulnList;
    }
    getAudit() {
        return this.execShellCommand('npm audit --json');
    }
    getDependencyTree(workspace) {
        const cmd = workspace ? `npm ls --all --json --workspace ${JSON.stringify(workspace)}` : `npm ls --all --json`;
        return this.execShellCommand(cmd);
    }
    execShellCommand(cmd) {
        try {
            return JSON.parse((0, node_child_process_1.execSync)(cmd, { stdio: 'pipe' }).toString());
        }
        catch (err) {
            const out = err?.stdout?.toString();
            if (!out)
                throw err;
            return JSON.parse(out);
        }
    }
    /**
     * Creates an .audit-summary.json file with current vulnerability counts for each root package
     */
    initConfigFile() {
        const configPath = path.join(process.cwd(), '.audit-summary.json');
        // Check if file already exists
        if (fs.existsSync(configPath)) {
            console.error(chalk_1.default.red('Error: .audit-summary.json already exists.'));
            console.log('Remove the existing file first if you want to reinitialize.');
            process.exit(1);
        }
        console.log('Initializing .audit-summary.json...');
        console.log('Analyzing current vulnerabilities...');
        // Get current vulnerability data
        const audit = this.getAudit();
        const tree = this.getDependencyTree();
        const rootsMap = this.buildRequiredByRootsMap(tree);
        const vulnerabilityList = Object.values(audit.vulnerabilities ?? {});
        // Build the config structure
        const config = {
            packages: {}
        };
        if (vulnerabilityList.length > 0) {
            const byRoot = this.getVulnerabilitiesByRoot(vulnerabilityList, rootsMap);
            const perRootCounts = this.getVulnerabilitiesPerRootCount(byRoot);
            // Sort packages alphabetically
            const sortedRoots = Array.from(perRootCounts.entries()).sort((a, b) => a[0].localeCompare(b[0]));
            // Add each root package with its current vulnerability counts
            for (const [root, { counts }] of sortedRoots) {
                config.packages[root] = {
                    severityThresholdCritical: counts.critical,
                    severityThresholdHigh: counts.high,
                    severityThresholdModerate: counts.moderate,
                    severityThresholdLow: counts.low
                };
            }
        }
        // Add default thresholds
        config.packages.default = {
            severityThresholdCritical: 0,
            severityThresholdHigh: 0,
            severityThresholdModerate: 0,
            severityThresholdLow: 0
        };
        // Write the config file
        try {
            fs.writeFileSync(configPath, JSON.stringify(config, null, 4), 'utf-8');
            console.log(chalk_1.default.green('✓ Successfully created .audit-summary.json'));
            console.log(`\nFile created at: ${configPath}`);
            console.log('\nThe file has been populated with current vulnerability counts for each package.');
            console.log('You can now adjust the thresholds as needed.');
        }
        catch (error) {
            console.error(chalk_1.default.red('Error writing .audit-summary.json:'), error);
            process.exit(1);
        }
    }
    /**
     * Load the .audit-summary.json config file if it exists
     */
    loadConfig() {
        const configPath = path.join(process.cwd(), '.audit-summary.json');
        if (!fs.existsSync(configPath)) {
            return null;
        }
        try {
            const configContent = fs.readFileSync(configPath, 'utf-8');
            return JSON.parse(configContent);
        }
        catch (error) {
            console.error(chalk_1.default.red('Error reading .audit-summary.json:'), error);
            return null;
        }
    }
    /**
     * Check if vulnerability counts exceed the thresholds defined in .audit-summary.json
     */
    checkThresholds(perRootCounts) {
        const config = this.loadConfig();
        if (!config) {
            // No config file, skip threshold checking
            return;
        }
        const violations = [];
        // Check each root package
        for (const [rootPackage, { counts }] of perRootCounts.entries()) {
            // Get thresholds for this package (or use default)
            const thresholds = config.packages[rootPackage] ?? config.packages.default;
            if (!thresholds) {
                // If no default is set, skip this package
                continue;
            }
            // Check each severity level
            if (counts.critical > thresholds.severityThresholdCritical) {
                violations.push({
                    package: rootPackage,
                    severity: 'critical',
                    current: counts.critical,
                    threshold: thresholds.severityThresholdCritical
                });
            }
            if (counts.high > thresholds.severityThresholdHigh) {
                violations.push({
                    package: rootPackage,
                    severity: 'high',
                    current: counts.high,
                    threshold: thresholds.severityThresholdHigh
                });
            }
            if (counts.moderate > thresholds.severityThresholdModerate) {
                violations.push({
                    package: rootPackage,
                    severity: 'moderate',
                    current: counts.moderate,
                    threshold: thresholds.severityThresholdModerate
                });
            }
            if (counts.low > thresholds.severityThresholdLow) {
                violations.push({
                    package: rootPackage,
                    severity: 'low',
                    current: counts.low,
                    threshold: thresholds.severityThresholdLow
                });
            }
        }
        // If there are violations, report them and exit
        if (violations.length > 0) {
            this.reportThresholdViolations(violations);
            process.exit(1);
        }
    }
    /**
     * Report threshold violations to the console
     */
    reportThresholdViolations(violations) {
        console.error();
        console.error(chalk_1.default.red.bold('✗ Vulnerability threshold exceeded!'));
        console.error();
        console.error('The following packages have more vulnerabilities than allowed:');
        console.error();
        for (const v of violations) {
            const severityColor = v.severity === 'critical'
                ? chalk_1.default.magentaBright.bold
                : v.severity === 'high'
                    ? chalk_1.default.redBright.bold
                    : v.severity === 'moderate'
                        ? chalk_1.default.yellowBright.bold
                        : chalk_1.default.white;
            console.error(`  ${chalk_1.default.bold(v.package)} - ${severityColor(v.severity)}: ` + `${chalk_1.default.red(v.current)} (threshold: ${v.threshold})`);
        }
        console.error();
        console.error('Please review and fix the vulnerabilities, or update the thresholds in .audit-summary.json');
        console.error();
    }
    /**
     * Fetch the latest available version for each root package from npm registry
     */
    getLatestVersions(rootPackages) {
        const latestVersions = new Map();
        for (const pkg of rootPackages) {
            try {
                const result = (0, node_child_process_1.execSync)(`npm view ${JSON.stringify(pkg)} version`, {
                    stdio: 'pipe',
                    encoding: 'utf-8'
                })
                    .toString()
                    .trim();
                latestVersions.set(pkg, result);
            }
            catch (err) {
                // If package not found or error, set as 'unknown'
                latestVersions.set(pkg, 'unknown');
            }
        }
        return latestVersions;
    }
    normSeverity(s) {
        if (!s)
            return 'info';
        const lower = s.toLowerCase();
        return SEV_ORDER[lower] !== undefined ? lower : 'info';
    }
    pad(s, w) {
        const str = String(s);
        if (str.length >= w)
            return str;
        return str + ' '.repeat(w - str.length);
    }
    /**
     * Build a map: packageName -> Set of top-level roots that require it.
     * We walk the npm ls tree once. Child node names come from the `dependencies` keys.
     */
    buildRequiredByRootsMap(tree) {
        const requiredByRoots = new Map();
        const visitedPaths = new Set();
        function add(name, root) {
            let set = requiredByRoots.get(name);
            if (!set) {
                set = new Set();
                requiredByRoots.set(name, set);
            }
            set.add(root);
        }
        function walk(node, currentRoot, pathKey) {
            if (!node || typeof node !== 'object')
                return;
            if (visitedPaths.has(pathKey))
                return;
            visitedPaths.add(pathKey);
            const deps = node.dependencies ?? {};
            for (const [childName, childNode] of Object.entries(deps)) {
                add(childName, currentRoot);
                const childVer = childNode?.version ?? '?';
                walk(childNode, currentRoot, `${pathKey}>${childName}@${childVer}`);
            }
        }
        const topLevel = tree.dependencies ?? {};
        for (const [topName, topNode] of Object.entries(topLevel)) {
            // Map a top-level dependency to itself (covers direct vulns)
            add(topName, topName);
            const ver = topNode?.version ?? '?';
            walk(topNode, topName, `${topName}@${ver}`);
        }
        return requiredByRoots;
    }
}
exports.default = AuditSumary;
