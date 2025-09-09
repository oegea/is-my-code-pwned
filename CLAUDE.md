# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **is-my-code-pwned**, a comprehensive Node.js CLI security scanner that detects malicious npm packages and analyzes vulnerability risks in projects. The tool performs exhaustive scanning of all possible locations where malicious packages could hide.

## Architecture

- **Modular design**: Refactored from single-file to multiple organized modules
- **Main entry point**: `index-new.js` orchestrates all components
- **Core modules**:
  - `src/database.js`: Manages malicious package database from `malicious-packages.json`
  - `src/scanner.js`: Comprehensive scanning engine with deep nested scanning
  - `src/risk-analyzer.js`: Advanced vulnerability and configuration analysis
  - `src/reporter.js`: Enhanced output formatting and reporting
  - `src/cli.js`: Command-line interface handling
  - `src/logger.js`: Centralized logging system

## Key Features

**Exhaustive Scanning:**
- Recursively scans ALL node_modules directories (including nested ones)
- Scans global packages across npm, yarn, and pnpm
- Examines package manager caches
- Deep analysis of package.json, lock files, and configurations
- Scans .npmrc files (local and global) for security issues

**Advanced Risk Analysis:**
- Detects vulnerable dependency ranges that could install malicious versions
- Analyzes dangerous package scripts
- Checks for insecure registries and configurations  
- Validates lock file integrity
- Examines environment variables for security risks

## Commands

**Enhanced CLI options:**
```bash
# Standard scan
node index.js

# Deep comprehensive scan (includes caches)
node index.js --deep-scan

# Configuration analysis only (fast)
node index.js --config-only

# Scan with cache checking
node index.js --scan-caches

# Verbose output with detailed logs
node index.js -v --log-file security-report.json

# JSON output for automation
node index.js --json

# Scan specific project
node index.js /path/to/project

# Available npm scripts
npm run scan          # Standard scan
npm run scan:deep     # Deep scan
npm run scan:config   # Config only
```

**Test the enhanced scanner:**
```bash
node index.js --help
node index.js --deep-scan -v
```

## Development Notes

- **No build process**: Pure Node.js, no compilation needed
- **No external dependencies**: Uses only Node.js built-in modules
- **Modular architecture**: Easy to extend and maintain
- **Comprehensive logging**: Detailed logging with multiple levels
- **Multiple output formats**: Console, JSON, and detailed file reports
- **Exit codes**: 0=safe, 1=risks found, 2=malicious packages, 3=fatal error

## Database Management

**Adding new malicious packages:**
Edit `malicious-packages.json`:
```json
{
  "package-name": "malicious-version",
  "another-package": "1.2.3"
}
```

The database is automatically loaded and validated at startup.

## Security Features

**CRITICAL - This scanner is designed to be ABSOLUTELY THOROUGH:**
- ✅ Scans nested node_modules recursively (up to 15 levels deep)
- ✅ Checks ALL global package locations (npm, yarn, pnpm)
- ✅ Analyzes package manager caches for suspicious content
- ✅ Validates lock file integrity and sources
- ✅ Detects vulnerable version ranges in package.json
- ✅ Checks .npmrc and configuration files for security issues
- ✅ Analyzes package scripts for dangerous commands
- ✅ Validates registry configurations
- ✅ Provides actionable security recommendations

## Important Security Context

This is a defensive security tool designed to give users COMPLETE CONFIDENCE that their project is clean. The scanner is intentionally comprehensive and may be slower than simple tools, but provides exhaustive coverage to ensure nothing malicious is missed.

**When adding features, maintain the principle of COMPREHENSIVE SECURITY - it's better to be thorough than fast.**