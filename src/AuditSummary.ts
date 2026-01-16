import { OptionValues } from 'commander';
import { AuditJson, AuditVulnerability, PerRootCounts, RootEntry, Severity, VulnerabilityView } from './types/Vulnerability';
import { execSync } from 'node:child_process';
import { NpmLsNode, NpmLsTree } from './types/Npm';
import { AsciiTable3 } from 'ascii-table3';
import chalk from 'chalk';
import * as fs from 'node:fs';
import * as path from 'node:path';

const SEV_ORDER: Record<Severity, number> = {
    critical: 4,
    high: 3,
    moderate: 2,
    low: 1,
    info: 0
};
const SEV_KEYS: Severity[] = ['critical', 'high', 'moderate', 'low', 'info'];

interface PackageThresholds {
    severityThresholdCritical: number;
    severityThresholdHigh: number;
    severityThresholdModerate: number;
    severityThresholdLow: number;
}

interface AuditConfig {
    packages: {
        [packageName: string]: PackageThresholds;
        default: PackageThresholds;
    };
}

export default class AuditSumary {
    private options: OptionValues;
    private packageName: string;

    constructor(options: OptionValues, packageName: string) {
        this.options = options;
        this.packageName = packageName;
    }

    public executeAudit() {
        // Handle init flag
        if (this.options.init) {
            this.initConfigFile();
            return;
        }

        const jsonMode = this.options.json ?? (false as boolean);
        const wsIdx = this.options.workspace as string;

        const audit = this.getAudit();
        const tree = this.getDependencyTree();
        const rootsMap = this.buildRequiredByRootsMap(tree);

        const vulnerabilityList = this.getVulnerabilityList(audit, jsonMode);

        if (vulnerabilityList) {
            const byRoot = this.getVulnerabilitiesByRoot(vulnerabilityList, rootsMap);
            const perRootCounts = this.getVulnerabilitiesPerRootCount(byRoot);

            // Global totals
            const global = SEV_KEYS.reduce((acc, k) => ((acc[k] = 0), acc), {} as Record<Severity, number>);

            for (const { counts } of perRootCounts.values()) {
                for (const k of SEV_KEYS) global[k] += counts[k];
            }

            const globalTotal = SEV_KEYS.reduce((acc, k) => acc + global[k], 0);
            const globalCounts: PerRootCounts = {
                ...global,
                total: globalTotal
            };

            // Fetch latest versions for root packages
            const rootPackages = Array.from(byRoot.keys());
            const latestVersions = this.getLatestVersions(rootPackages);

            // Output
            if (jsonMode) {
                this.outputJSON(perRootCounts, globalCounts, tree, latestVersions);
            } else {
                this.outputTerminal(byRoot, perRootCounts, globalCounts, tree, latestVersions);
                // Check thresholds if config file exists
                this.checkThresholds(perRootCounts);
            }
        }
    }

    private outputTerminal(
        byRoot: Map<string, VulnerabilityView[]>,
        perRootCounts: Map<string, { vulns: VulnerabilityView[]; counts: PerRootCounts }>,
        globalCounts: PerRootCounts,
        tree: NpmLsTree,
        latestVersions: Map<string, string>
    ) {
        const verbose = this.options.verbose ?? (false as boolean);
        const sortedRoots = Array.from(byRoot.keys()).sort((a, b) => a.localeCompare(b));

        // Extract versions for root packages
        const rootVersions = new Map<string, string>();
        const topLevel = tree.dependencies ?? {};
        for (const [topName, topNode] of Object.entries(topLevel)) {
            rootVersions.set(topName, topNode?.version ?? 'unknown');
        }

        function coloredSeverity(severity: Severity) {
            switch (SEV_ORDER[severity]) {
                case 4:
                    return chalk.magentaBright.bold(severity);
                case 3:
                    return chalk.redBright.bold(severity);
                case 2:
                    return chalk.yellowBright.bold(severity);
                default:
                    return severity;
            }
        }

        if (verbose) {
            for (const root of sortedRoots) {
                const record = perRootCounts.get(root);
                if (!record) continue;

                // Sort by severity desc then name
                record.vulns.sort((a, b) => {
                    const sa = SEV_ORDER[a.severity];
                    const sb = SEV_ORDER[b.severity];
                    if (sb !== sa) return sb - sa;
                    return a.name.localeCompare(b.name);
                });

                const currentVersion = rootVersions.get(root);
                const latestVersion = latestVersions.get(root);
                const versionInfo =
                    currentVersion && latestVersion ? `${currentVersion} → latest: ${latestVersion}` : currentVersion ? currentVersion : '';
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
            chalk.bold('TOTAL'),
            '',
            '',
            chalk.magentaBright.bold(globalCounts.critical),
            chalk.redBright.bold(globalCounts.high),
            chalk.yellowBright.bold(globalCounts.moderate),
            chalk.bold(globalCounts.low),
            chalk.bold(globalCounts.info),
            chalk.bold(globalCounts.total)
        ];

        rowArrays.push(footer);

        const table = new AsciiTable3('NPM Packages Audit Summary (deduped by package per root dependency)')
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

    private getAllRootsRowData(
        rootsByTotalDesc: [string, { vulns: VulnerabilityView[]; counts: PerRootCounts }][],
        rootVersions: Map<string, string>,
        latestVersions: Map<string, string>
    ) {
        const rowArrays = [];

        for (const [root, { counts }] of rootsByTotalDesc) {
            const coloredRoot = counts.critical
                ? chalk.magentaBright.bold(root)
                : counts.high
                ? chalk.redBright.bold(root)
                : counts.moderate
                ? chalk.yellowBright.bold(root)
                : root;
            const currentVersion = rootVersions.get(root) ?? '';
            const latestVersion = latestVersions.get(root) ?? '';
            const data = [
                coloredRoot,
                currentVersion,
                latestVersion,
                counts.critical ? chalk.magentaBright.bold(counts.critical) : '',
                counts.high ? chalk.redBright.bold(counts.high) : '',
                counts.moderate ? chalk.yellowBright.bold(counts.moderate) : '',
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
    private outputJSON(
        perRootCounts: Map<string, { vulns: VulnerabilityView[]; counts: PerRootCounts }>,
        globalCounts: PerRootCounts,
        tree: NpmLsTree,
        latestVersions: Map<string, string>
    ) {
        // Extract versions for root packages
        const rootVersions = new Map<string, string>();
        const topLevel = tree.dependencies ?? {};
        for (const [topName, topNode] of Object.entries(topLevel)) {
            rootVersions.set(topName, topNode?.version ?? 'unknown');
        }

        const rootsJson = Object.fromEntries(
            Array.from(perRootCounts.entries()).map(([root, { vulns, counts }]) => [
                root,
                {
                    currentVersion: rootVersions.get(root) ?? 'unknown',
                    latestVersion: latestVersions.get(root) ?? 'unknown',
                    vulnerabilities: vulns,
                    summary: counts
                }
            ])
        );
        const out = { roots: rootsJson, global: globalCounts };
        console.log(JSON.stringify(out, null, 2));
        return;
    }

    private sortRootsBySeverity(perRootCounts: Map<string, { vulns: VulnerabilityView[]; counts: PerRootCounts }>): RootEntry[] {
        // Define the priority order explicitly to avoid relying on object key order.
        const severityOrder: (keyof PerRootCounts)[] = ['critical', 'high', 'moderate', 'low', 'info'];

        return Array.from(perRootCounts.entries()).sort((a, b) => {
            const aCounts = a[1].counts;
            const bCounts = b[1].counts;

            // Compare each severity dimension in order
            for (const sev of severityOrder) {
                const diff = bCounts[sev] - aCounts[sev];
                if (diff !== 0) return diff;
            }

            // Optional: fallback to total if you still want that as a differentiator
            const totalDiff = bCounts.total - aCounts.total;
            if (totalDiff !== 0) return totalDiff;

            // Final stable tie-breaker: alphabetical by package/root name
            return a[0].localeCompare(b[0]);
        });
    }

    /**
     * Build per-root deduped lists & counts
     */
    private getVulnerabilitiesPerRootCount(vulnerabilitiesByRoot: Map<string, VulnerabilityView[]>) {
        const perRootCounts = new Map<string, { vulns: VulnerabilityView[]; counts: PerRootCounts }>();

        for (const [root, list] of vulnerabilitiesByRoot.entries()) {
            // Deduplicate by vulnerable package name per root
            const dedup = Array.from(new Map(list.map((x) => [x.name, x])).values());

            // Counts
            const counts = SEV_KEYS.reduce((acc, k) => ((acc[k] = 0), acc), {} as Record<Severity, number>);
            for (const v of dedup) counts[v.severity]++;
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
     * Uses the `nodes` field from npm audit to determine which root dependencies
     * are actually affected by each vulnerability, preventing false positives when
     * a non-vulnerable version of a package exists as a root dependency alongside
     * vulnerable versions in nested dependencies.
     * @param vulnerabilityList
     * @param rootsMap
     */
    private getVulnerabilitiesByRoot(vulnerabilityList: AuditVulnerability[], rootsMap: Map<string, Set<string>>) {
        const byRoot = new Map<string, VulnerabilityView[]>();

        for (const v of vulnerabilityList) {
            const severity = this.normSeverity(v.severity);
            let targetRoots: string[] = [];
            
            // Use the `nodes` field if available to determine which roots are affected
            if (v.nodes && v.nodes.length > 0) {
                // Extract root package names from node paths
                // Example: "node_modules/@ui5/cli/node_modules/glob" -> "@ui5/cli"
                //          "node_modules/glob" -> "glob"
                const affectedRoots = new Set<string>();
                
                for (const nodePath of v.nodes) {
                    const root = this.extractRootFromNodePath(nodePath);
                    if (root) {
                        affectedRoots.add(root);
                    }
                }
                
                targetRoots = Array.from(affectedRoots);
            } else {
                // Fallback to old behavior if nodes field is not available
                // This is less accurate but provides reasonable coverage
                let roots = Array.from(rootsMap.get(v.name) ?? []);
                
                // Special case: If the vulnerable package name matches one of its roots,
                // exclude the self-reference. This handles the common case where:
                // - Package X version A (non-vulnerable) is a root dependency
                // - Package X version B (vulnerable) is a nested dependency of another root
                // Without the nodes field, we can't distinguish versions, but we can assume
                // that if X is both a root and has vulnerabilities, the root version is likely
                // not the vulnerable one (npm would typically resolve to the latest safe version).
                // Note: This is a heuristic and may occasionally be incorrect, but it prevents
                // more false positives than it creates false negatives.
                if (roots.includes(v.name)) {
                    roots = roots.filter(r => r !== v.name);
                }
                
                targetRoots = roots;
            }
            
            if (targetRoots.length === 0) {
                targetRoots = ['(unresolved root)'];
            }

            for (const r of targetRoots) {
                const arr = byRoot.get(r) ?? [];
                arr.push({ name: v.name, severity, range: v.range });
                byRoot.set(r, arr);
            }
        }

        return byRoot;
    }
    
    /**
     * Extract the root package name from a node_modules path.
     * Examples:
     *   "node_modules/@ui5/cli/node_modules/glob" -> "@ui5/cli"
     *   "node_modules/glob" -> "glob"
     *   "node_modules/@scope/package/node_modules/dep" -> "@scope/package"
     */
    private extractRootFromNodePath(nodePath: string): string | null {
        // Normalize path and split by node_modules to get path segments
        // npm always uses forward slashes, even on Windows
        const normalized = nodePath.replace(/\\/g, '/').trim();
        const parts = normalized.split('node_modules/').filter(p => p.trim().length > 0);
        
        if (parts.length === 0) {
            return null;
        }
        
        // The first segment after the first 'node_modules/' contains the root package
        // For example: "node_modules/@ui5/cli/node_modules/glob" splits to ["@ui5/cli/", "glob"]
        // We take the first segment: "@ui5/cli/"
        const firstPart = parts[0];
        
        if (!firstPart) {
            return null;
        }
        
        // Handle scoped packages (@scope/package)
        if (firstPart.startsWith('@')) {
            // For scoped packages, we need to extract both scope and package name
            // Format: @scope/package/... or @scope/package
            const scopedParts = firstPart.split('/');
            if (scopedParts.length >= 2) {
                return `${scopedParts[0]}/${scopedParts[1]}`;
            }
            // Malformed scoped package (missing package name), return null
            return null;
        }
        
        // For non-scoped packages, take everything before the first slash (if any)
        const slashIndex = firstPart.indexOf('/');
        if (slashIndex > 0) {
            return firstPart.substring(0, slashIndex);
        }
        
        // If no slash, the whole part is the package name
        return firstPart;
    }

    private getVulnerabilityList(audit: AuditJson, jsonMode: boolean) {
        const vulnList: AuditVulnerability[] = Object.values(audit.vulnerabilities ?? {});

        if (vulnList.length === 0) {
            if (jsonMode) {
                // Emit empty structure for consistency
                const emptyCounts: PerRootCounts = {
                    critical: 0,
                    high: 0,
                    moderate: 0,
                    low: 0,
                    info: 0,
                    total: 0
                };

                console.info(JSON.stringify({ roots: {}, global: emptyCounts }, null, 2));
            } else {
                console.info('No vulnerabilities found.');
            }
            return;
        }

        return vulnList;
    }

    private getAudit(): AuditJson {
        return this.execShellCommand('npm audit --json');
    }

    private getDependencyTree(workspace?: string): NpmLsTree {
        const cmd = workspace ? `npm ls --all --json --workspace ${JSON.stringify(workspace)}` : `npm ls --all --json`;

        return this.execShellCommand(cmd);
    }

    private execShellCommand(cmd: string) {
        try {
            return JSON.parse(execSync(cmd, { stdio: 'pipe' }).toString());
        } catch (err: any) {
            const out = err?.stdout?.toString();
            if (!out) throw err;
            return JSON.parse(out);
        }
    }

    /**
     * Creates an .audit-summary.json file with current vulnerability counts for each root package
     */
    private initConfigFile() {
        const configPath = path.join(process.cwd(), '.audit-summary.json');

        // Check if file already exists
        if (fs.existsSync(configPath)) {
            console.error(chalk.red('Error: .audit-summary.json already exists.'));
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
        const config: any = {
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
            console.log(chalk.green('✓ Successfully created .audit-summary.json'));
            console.log(`\nFile created at: ${configPath}`);
            console.log('\nThe file has been populated with current vulnerability counts for each package.');
            console.log('You can now adjust the thresholds as needed.');
        } catch (error) {
            console.error(chalk.red('Error writing .audit-summary.json:'), error);
            process.exit(1);
        }
    }

    /**
     * Load the .audit-summary.json config file if it exists
     */
    private loadConfig(): AuditConfig | null {
        const configPath = path.join(process.cwd(), '.audit-summary.json');

        if (!fs.existsSync(configPath)) {
            return null;
        }

        try {
            const configContent = fs.readFileSync(configPath, 'utf-8');
            return JSON.parse(configContent) as AuditConfig;
        } catch (error) {
            console.error(chalk.red('Error reading .audit-summary.json:'), error);
            return null;
        }
    }

    /**
     * Check if vulnerability counts exceed the thresholds defined in .audit-summary.json
     */
    private checkThresholds(perRootCounts: Map<string, { vulns: VulnerabilityView[]; counts: PerRootCounts }>) {
        const config = this.loadConfig();

        if (!config) {
            // No config file, skip threshold checking
            return;
        }

        const violations: Array<{
            package: string;
            severity: string;
            current: number;
            threshold: number;
        }> = [];

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
    private reportThresholdViolations(
        violations: Array<{
            package: string;
            severity: string;
            current: number;
            threshold: number;
        }>
    ) {
        console.error();
        console.error(chalk.red.bold('✗ Vulnerability threshold exceeded!'));
        console.error();
        console.error('The following packages have more vulnerabilities than allowed:');
        console.error();

        for (const v of violations) {
            const severityColor =
                v.severity === 'critical'
                    ? chalk.magentaBright.bold
                    : v.severity === 'high'
                    ? chalk.redBright.bold
                    : v.severity === 'moderate'
                    ? chalk.yellowBright.bold
                    : chalk.white;

            console.error(`  ${chalk.bold(v.package)} - ${severityColor(v.severity)}: ` + `${chalk.red(v.current)} (threshold: ${v.threshold})`);
        }

        console.error();
        console.error('Please review and fix the vulnerabilities, or update the thresholds in .audit-summary.json');
        console.error();
    }

    /**
     * Fetch the latest available version for each root package from npm registry
     */
    private getLatestVersions(rootPackages: string[]): Map<string, string> {
        const latestVersions = new Map<string, string>();

        for (const pkg of rootPackages) {
            try {
                const result = execSync(`npm view ${JSON.stringify(pkg)} version`, {
                    stdio: 'pipe',
                    encoding: 'utf-8'
                })
                    .toString()
                    .trim();
                latestVersions.set(pkg, result);
            } catch (err) {
                // If package not found or error, set as 'unknown'
                latestVersions.set(pkg, 'unknown');
            }
        }

        return latestVersions;
    }

    private normSeverity(s?: string): Severity {
        if (!s) return 'info';
        const lower = s.toLowerCase() as Severity;
        return (SEV_ORDER as Record<string, number>)[lower] !== undefined ? lower : 'info';
    }

    private pad(s: string | number, w: number): string {
        const str = String(s);
        if (str.length >= w) return str;
        return str + ' '.repeat(w - str.length);
    }

    /**
     * Build a map: packageName -> Set of top-level roots that require it.
     * We walk the npm ls tree once. Child node names come from the `dependencies` keys.
     */
    private buildRequiredByRootsMap(tree: NpmLsTree): Map<string, Set<string>> {
        const requiredByRoots = new Map<string, Set<string>>();
        const visitedPaths = new Set<string>();

        function add(name: string, root: string) {
            let set = requiredByRoots.get(name);
            if (!set) {
                set = new Set<string>();
                requiredByRoots.set(name, set);
            }
            set.add(root);
        }

        function walk(node: NpmLsNode, currentRoot: string, pathKey: string) {
            if (!node || typeof node !== 'object') return;
            if (visitedPaths.has(pathKey)) return;

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
