# is-my-code-pwned

🛡️ **Advanced security scanner for Node.js projects**

Comprehensive tool that detects malicious npm packages and analyzes security vulnerabilities in your projects. Designed to give you complete confidence that your code is clean.

> ⚠️ **DISCLAIMER**: This tool was developed with Claude Code AI assistance. **Use with caution** in production environments. The tool is designed to be **read-only** and will not modify your files or projects - it only analyzes and reports security findings. Always review the source code before use.

## 🚀 Installation

### Global installation (recommended for CLI usage)
```bash
npm install -g is-my-code-pwned
```

### Local installation
```bash
npm install --save-dev is-my-code-pwned
```

## 📋 Usage

### Command Line Interface
```bash
# Quick scan current directory
is-my-code-pwned

# Deep comprehensive scan (includes caches)
is-my-code-pwned --deep-scan

# Scan specific project
is-my-code-pwned /path/to/project

# Configuration analysis only (fast)
is-my-code-pwned --config-only

# Verbose output with detailed logs
is-my-code-pwned -v

# JSON output for automation
is-my-code-pwned --json

# Save detailed report
is-my-code-pwned --log-file security-report.json
```

### Options
- `--help` - Show help
- `--verbose, -v` - Show detailed scan log  
- `--json` - JSON output format
- `--log-file FILE` - Save detailed report
- `--scan-caches` - Include package manager caches
- `--deep-scan` - Maximum depth scanning (slower but thorough)
- `--config-only` - Only analyze configuration files

## 🔍 What it scans

✅ **Exhaustive package scanning:**
- All node_modules directories (including nested ones)
- Global packages (npm, yarn, pnpm)
- Package manager caches
- Scoped packages (@org/package)

✅ **Configuration analysis:**
- package.json for vulnerable version ranges
- Lock files (package-lock.json, yarn.lock, pnpm-lock.yaml)
- .npmrc files (local and global)
- Environment variables
- Package scripts for dangerous commands

✅ **Security validations:**
- Registry configurations
- Authentication token exposure
- TLS settings
- File gitignore status

## 🚨 Security Features

This scanner is designed to be **absolutely thorough** - it checks everywhere malicious packages could hide:

- **Deep nested scanning** up to 15 levels
- **All package managers** (npm, yarn, pnpm)  
- **Cache inspection** for suspicious content
- **Smart registry validation** - distinguishes between configured private registries and unknown sources
- **Git integration** - checks if sensitive files are properly ignored
- **Actionable recommendations** - tells you exactly what to fix and how

## 📊 Output

The tool provides clear, actionable output:

```bash
🛡️ SECURITY SUMMARY & NEXT ACTIONS

🚨 CRITICAL (1):
   • chalk version range allows malicious 5.6.1

🔴 HIGH (1):
   • No lock file - versions not pinned (supply chain attack risk)

FIX THESE NOW:
   1. Pin chalk to safe version (change "^5.0.0" to exact version, NOT 5.6.1)
   2. Create lock file: run "npm install" or "yarn install"
```

## 🛠️ Exit Codes

- `0` - No issues found
- `1` - Security risks detected  
- `2` - Malicious packages found
- `3` - Fatal error

## 🔧 Adding New Malicious Packages

Update `malicious-packages.json`:
```json
{
  "package-name": "malicious-version",
  "another-package": "1.2.3"
}
```

## 🤝 Contributing

This is a defensive security tool. When adding features, maintain the principle of **comprehensive security** - it's better to be thorough than fast.
