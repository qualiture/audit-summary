# audit-summary

A powerful CLI tool that provides a clear, organized summary of NPM package vulnerabilities grouped by root dependencies. Track security issues, set thresholds, and monitor which packages need updates - all with beautiful, color-coded output.

## Why audit-summary?

While `npm audit` provides detailed vulnerability information, it can be overwhelming and difficult to prioritize. **audit-summary** solves this by:

-   📦 **Grouping vulnerabilities by root dependency** - See which top-level packages are causing issues
-   🎯 **Deduplicating vulnerabilities** - No more counting the same issue multiple times per package
-   📊 **Clear severity breakdown** - Instant overview of critical, high, moderate, and low severity issues
-   🚨 **Threshold enforcement** - Set limits and fail CI/CD builds when thresholds are exceeded
-   📈 **Version tracking** - See current vs. latest versions for all root packages
-   💅 **Beautiful output** - Color-coded tables and verbose modes for easy reading

## Installation

### Global Installation (Recommended)

```bash
npm install -g audit-summary
```

### Local Installation (Per Project)

```bash
npm install --save-dev audit-summary
```

## Usage

### Basic Command

Run a security audit with a summary view:

```bash
audit-summary
```

This displays a table showing vulnerability counts for each root dependency:

```
╭─────────────────────────────────────────────────────────────────────────────╮
│ NPM Packages Audit Summary (deduped by package per root dependency)        │
├──────────────────┬─────────┬─────────┬──────────┬──────┬──────────┬─────────┤
│ Root Dependency  │ Current │ Latest  │ Critical │ High │ Moderate │ Low │...│
├──────────────────┼─────────┼─────────┼──────────┼──────┼──────────┼─────────┤
│ express          │ 4.18.2  │ 4.19.0  │        2 │    3 │        5 │   1 │...│
│ lodash           │ 4.17.20 │ 4.17.21 │        0 │    1 │        0 │   0 │...│
│ axios            │ 0.21.1  │ 1.6.0   │        1 │    0 │        2 │   0 │...│
├──────────────────┼─────────┼─────────┼──────────┼──────┼──────────┼─────────┤
│ TOTAL            │         │         │        3 │    4 │        7 │   1 │...│
╰──────────────────┴─────────┴─────────┴──────────┴──────┴──────────┴─────────╯
```

### Command Line Options

#### `-v, --verbose`

Show detailed vulnerability information for each package:

```bash
audit-summary --verbose
```

Output:

```
express (4.18.2 → latest: 4.19.0)
  - send [critical] (affected: <0.18.0)
  - serve-static [critical] (affected: <1.15.0)
  - qs [high] (affected: <6.11.0)
  Summary: 2 critical, 3 high, 5 moderate, 1 low
-----
lodash (4.17.20 → latest: 4.17.21)
  - lodash [high] (affected: <4.17.21)
  Summary: 1 high
-----
```

#### `-j, --json`

Output results in JSON format for programmatic use:

```bash
audit-summary --json
```

Output:

```json
{
    "roots": {
        "express": {
            "currentVersion": "4.18.2",
            "latestVersion": "4.19.0",
            "vulnerabilities": [
                {
                    "name": "send",
                    "severity": "critical",
                    "range": "<0.18.0"
                }
            ],
            "summary": {
                "critical": 2,
                "high": 3,
                "moderate": 5,
                "low": 1,
                "info": 0,
                "total": 11
            }
        }
    },
    "global": {
        "critical": 3,
        "high": 4,
        "moderate": 7,
        "low": 1,
        "info": 0,
        "total": 15
    }
}
```

#### `-i, --init`

Create a `.audit-summary.json` configuration file with current vulnerability counts as baseline thresholds:

```bash
audit-summary --init
```

This creates a config file like:

```json
{
    "packages": {
        "express": {
            "severityThresholdCritical": 2,
            "severityThresholdHigh": 3,
            "severityThresholdModerate": 5,
            "severityThresholdLow": 1
        },
        "lodash": {
            "severityThresholdCritical": 0,
            "severityThresholdHigh": 1,
            "severityThresholdModerate": 0,
            "severityThresholdLow": 0
        },
        "default": {
            "severityThresholdCritical": 0,
            "severityThresholdHigh": 0,
            "severityThresholdModerate": 0,
            "severityThresholdLow": 0
        }
    }
}
```

#### `-w, --workspace <name>`

Run audit for a specific workspace in an NPM monorepo:

```bash
audit-summary --workspace my-package
```

## Threshold Enforcement

### Setting Up Thresholds

1. Initialize the configuration file:

    ```bash
    audit-summary --init
    ```

2. Edit `.audit-summary.json` to set your desired thresholds:

    ```json
    {
        "packages": {
            "express": {
                "severityThresholdCritical": 0,
                "severityThresholdHigh": 2,
                "severityThresholdModerate": 5,
                "severityThresholdLow": 10
            },
            "default": {
                "severityThresholdCritical": 0,
                "severityThresholdHigh": 0,
                "severityThresholdModerate": 3,
                "severityThresholdLow": 5
            }
        }
    }
    ```

3. Run audit-summary - it will check against your thresholds:
    ```bash
    audit-summary
    ```

### How Thresholds Work

-   If a `.audit-summary.json` file exists, the tool automatically checks vulnerability counts against configured thresholds
-   **Package-specific thresholds**: If a package is listed in the config, its specific thresholds are used
-   **Default thresholds**: Packages not listed use the `default` thresholds
-   **Violations**: If any threshold is exceeded, the tool:
    -   Displays a detailed error message
    -   Lists all violations
    -   Exits with code 1 (fails CI/CD builds)

Example violation output:

```
✗ Vulnerability threshold exceeded!

The following packages have more vulnerabilities than allowed:

  express - critical: 2 (threshold: 0)
  lodash - high: 3 (threshold: 2)
  axios - moderate: 8 (threshold: 5)

Please review and fix the vulnerabilities, or update the thresholds in .audit-summary.json
```

## Use Cases

### 1. Daily Security Monitoring

```bash
# Quick check of your project's security status
audit-summary
```

### 2. CI/CD Pipeline Integration

Add to your CI/CD pipeline to enforce security standards:

```yaml
# .github/workflows/security.yml
name: Security Audit
on: [push, pull_request]
jobs:
    audit:
        runs-on: ubuntu-latest
        steps:
            - uses: actions/checkout@v2
            - uses: actions/setup-node@v2
            - run: npm install -g audit-summary
            - run: audit-summary # Fails if thresholds exceeded
```

### 3. Identify Update Priorities

Use verbose mode to see which packages need updates:

```bash
audit-summary --verbose
```

Look for packages where current version differs from latest version, especially those with high severity issues.

### 4. Team Reporting

Generate JSON output for custom reporting or dashboards:

```bash
audit-summary --json > security-report.json
```

### 5. Workspace-Specific Audits

In monorepos, audit individual packages:

```bash
audit-summary --workspace @mycompany/api
audit-summary --workspace @mycompany/frontend
```

## Examples

### Example 1: Basic Security Check

```bash
$ audit-summary

╭───────────────────────────────────────────────────────────╮
│ NPM Packages Audit Summary                               │
├──────────────────┬─────────┬─────────┬──────────┬────────┤
│ Root Dependency  │ Current │ Latest  │ Critical │ High...│
├──────────────────┼─────────┼─────────┼──────────┼────────┤
│ express          │ 4.18.2  │ 4.19.0  │        0 │    2...│
│ react            │ 17.0.2  │ 18.2.0  │        0 │    0...│
├──────────────────┼─────────┼─────────┼──────────┼────────┤
│ TOTAL            │         │         │        0 │    2...│
╰──────────────────┴─────────┴─────────┴──────────┴────────╯
```

### Example 2: Detailed Investigation with Verbose Mode

```bash
$ audit-summary --verbose

express (4.18.2 → latest: 4.19.0)
  - qs [high] (affected: <6.11.0)
  - send [high] (affected: <0.18.0)
  - path-to-regexp [moderate] (affected: <0.1.10)
  Summary: 2 high, 1 moderate
-----

react (17.0.2 → latest: 18.2.0)
  Summary: 0
-----

╭───────────────────────────────────────────────────────────╮
│ NPM Packages Audit Summary                               │
│ ...                                                       │
╰───────────────────────────────────────────────────────────╯
```

## How It Works

1. **Runs npm audit** - Leverages npm's built-in security audit
2. **Analyzes dependency tree** - Uses `npm ls` to understand package relationships
3. **Groups by root** - Maps vulnerabilities to their root-level dependencies
4. **Deduplicates** - Counts each unique vulnerable package once per root
5. **Checks thresholds** - Validates against `.audit-summary.json` if present
6. **Formats output** - Presents results in table, verbose, or JSON format

## Requirements

-   Node.js >= 14
-   npm >= 7

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Standard MIT licence.

## Support

If you encounter any issues or have questions, please file an issue on the GitHub repository.

---

Made with ❤️ for better npm security monitoring
