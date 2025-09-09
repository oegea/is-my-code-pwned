const fs = require('fs');
const path = require('path');

class SecurityReporter {
  constructor(logger) {
    this.logger = logger;
  }

  generateSummary(maliciousPackages, risks, cacheResults, scanTime) {
    const criticalRisks = risks.filter(r => r.severity === 'critical').length;
    const highRisks = risks.filter(r => r.severity === 'high').length;
    const mediumRisks = risks.filter(r => r.severity === 'medium').length;
    const lowRisks = risks.filter(r => r.severity === 'low').length;
    
    const totalMalicious = maliciousPackages.length + (cacheResults?.length || 0);
    const isSafe = totalMalicious === 0 && criticalRisks === 0 && highRisks === 0;
    
    return {
      safe: isSafe,
      status: isSafe ? 'SECURE' : 'VULNERABLE',
      maliciousPackages: totalMalicious,
      risks: {
        critical: criticalRisks,
        high: highRisks,
        medium: mediumRisks,
        low: lowRisks,
        total: risks.length
      },
      scanTime,
      recommendation: this.getSecurityRecommendation(isSafe, criticalRisks, highRisks, totalMalicious)
    };
  }

  getSecurityRecommendation(isSafe, criticalRisks, highRisks, maliciousCount) {
    if (maliciousCount > 0) {
      return 'IMMEDIATE ACTION REQUIRED: Malicious packages detected. Remove them immediately and scan your system for compromise.';
    }
    
    if (criticalRisks > 0) {
      return 'URGENT: Critical security vulnerabilities detected. Fix immediately to prevent potential attacks.';
    }
    
    if (highRisks > 0) {
      return 'HIGH PRIORITY: Security risks detected that could lead to compromise. Address promptly.';
    }
    
    if (isSafe) {
      return 'Your code appears secure from known malicious packages and major vulnerabilities.';
    }
    
    return 'Some security improvements recommended. Review medium and low priority issues.';
  }

  printSummary(summary, maliciousPackages, risks, cacheResults, options) {
    const statusIcon = summary.safe ? '✅' : '🚨';
    const statusColor = summary.safe ? '\x1b[32m' : '\x1b[31m';
    const resetColor = '\x1b[0m';
    
    console.log('');
    console.log('═'.repeat(70));
    console.log(`${statusIcon} ${statusColor}SECURITY STATUS: ${summary.status}${resetColor}`);
    console.log('═'.repeat(70));
    
    if (!summary.safe) {
      this.printMaliciousPackages(maliciousPackages, cacheResults);
      this.printRiskSummary(summary, risks);
    } else {
      console.log('');
      console.log('🛡️  No malicious packages found');
      console.log('🔒 No critical or high security risks detected');
      console.log('✨ Your project appears to be secure!');
    }
    
    this.printScanStats(summary, options);
    
    // Security summary and recommendations at the end
    if (!summary.safe) {
      this.printSecuritySummaryAndActions(summary, risks, maliciousPackages);
    }
    
    if (options.verbose) {
      this.printDetailedAnalysis(risks);
    }
    
    if (options.logFile) {
      this.saveDetailedReport(options.logFile, summary, maliciousPackages, risks, cacheResults);
      console.log(`\n💾 Detailed security report saved to: ${options.logFile}`);
    }
    
    console.log('');
  }

  printMaliciousPackages(maliciousPackages, cacheResults) {
    const totalMalicious = maliciousPackages.length + (cacheResults?.length || 0);
    
    if (totalMalicious > 0) {
      console.log(`\n🦠 MALICIOUS PACKAGES DETECTED: ${totalMalicious}`);
      console.log('🚨 IMMEDIATE ACTION REQUIRED - REMOVE THESE PACKAGES NOW!');
      
      if (maliciousPackages.length > 0) {
        const byType = this.groupPackagesByType(maliciousPackages);
        
        for (const [type, packages] of Object.entries(byType)) {
          console.log(`\n📍 ${type.toUpperCase()} PACKAGES:`);
          for (const pkg of packages) {
            console.log(`   ❌ ${pkg.name}@${pkg.version}`);
            console.log(`      📁 ${pkg.path}`);
            console.log(`      🔧 REMOVE: rm -rf "${pkg.path}"`);
          }
        }
      }
      
      if (cacheResults && cacheResults.length > 0) {
        console.log('\n📦 CACHE WARNINGS:');
        for (const cache of cacheResults) {
          console.log(`   ⚠️  ${cache.type} cache may contain malicious packages`);
          console.log(`      🔧 CLEAR: Clear ${cache.type} cache`);
        }
      }
      
      console.log('\n🔥 POST-REMOVAL ACTIONS:');
      console.log('   1. Delete node_modules: rm -rf node_modules');
      console.log('   2. Clear npm cache: npm cache clean --force');
      console.log('   3. Reinstall dependencies: npm install');
      console.log('   4. Scan system for other signs of compromise');
      console.log('   5. Check for unauthorized file modifications');
    }
  }

  groupPackagesByType(packages) {
    const byType = {};
    for (const pkg of packages) {
      if (!byType[pkg.type]) byType[pkg.type] = [];
      byType[pkg.type].push(pkg);
    }
    return byType;
  }

  printRiskSummary(summary, risks) {
    if (summary.risks.total > 0) {
      console.log(`\n⚠️  SECURITY RISKS DETECTED: ${summary.risks.total}`);
      
      // Show the most important risks concisely
      const criticalRisks = risks.filter(r => r.severity === 'critical');
      const highRisks = risks.filter(r => r.severity === 'high');
      
      if (criticalRisks.length > 0) {
        console.log(`\n🚨 CRITICAL (${criticalRisks.length}):`);
        criticalRisks.slice(0, 3).forEach(risk => {
          console.log(`   • ${this.getShortRiskDescription(risk)}`);
        });
        if (criticalRisks.length > 3) {
          console.log(`   ... and ${criticalRisks.length - 3} more critical issues`);
        }
      }
      
      if (highRisks.length > 0) {
        console.log(`\n🔴 HIGH (${highRisks.length}):`);
        highRisks.slice(0, 2).forEach(risk => {
          console.log(`   • ${this.getShortRiskDescription(risk)}`);
        });
        if (highRisks.length > 2) {
          console.log(`   ... and ${highRisks.length - 2} more high priority issues`);
        }
      }
      
      const mediumRisks = risks.filter(r => r.severity === 'medium');
      const lowRisks = risks.filter(r => r.severity === 'low');
      
      if (mediumRisks.length > 0) {
        console.log(`\n🟡 MEDIUM: ${mediumRisks.length} issues (use -v for details)`);
      }
      if (lowRisks.length > 0) {
        console.log(`🔵 LOW: ${lowRisks.length} issues (use -v for details)`);
      }
    }
  }

  getShortRiskDescription(risk) {
    switch (risk.type) {
      case 'vulnerable-range':
        return `${risk.package} version range allows malicious ${risk.maliciousVersion}`;
      case 'no-lock-file':
        return 'No lock file - versions not pinned (supply chain attack risk)';
      case 'insecure-registry':
        const gitStatus = risk.gitIgnored ? ' (git-ignored)' : ' (will be committed!)';
        return `Insecure HTTP registry in use${gitStatus}`;
      case 'insecure-global-registry':
        return 'Global npm config uses insecure HTTP registry';
      case 'global-tls-disabled':
        return 'Global npm config disables SSL verification';
      case 'exposed-auth-token':
        const gitWarning = risk.gitIgnored ? ' (git-ignored but exposed)' : ' (will be committed to git!)';
        return `Auth token in .npmrc${gitWarning}`;
      case 'tls-disabled':
        return 'TLS certificate validation disabled (man-in-the-middle risk)';
      case 'dangerous-script':
        return `Script "${risk.script}" contains dangerous commands`;
      case 'suspicious-source':
        return `${risk.package} installed from untrusted source`;
      case 'multiple-lock-files':
        return 'Conflicting lock files (npm + yarn/pnpm)';
      case 'loose-dependency':
        return `${risk.package} uses wildcard version "${risk.version}"`;
      case 'outdated-package-manager':
        return `${risk.packageManager} v${risk.currentVersion} has known vulnerabilities`;
      case 'suspicious-registry-in-lock':
        return `Lock file uses unconfigured registry: ${risk.registry}`;
      case 'insecure-configured-registry':
        return `Your configured registry uses HTTP: ${risk.registry} (should use HTTPS)`;
      case 'no-integrity-hashes':
        return `Lock file missing integrity hashes (vulnerable to tampering)`;
      case 'invalid-lock-file':
        return `Lock file is corrupted: ${risk.lockFile}`;
      default:
        return risk.message;
    }
  }

  printSecuritySummaryAndActions(summary, risks, maliciousPackages) {
    console.log('\n' + '═'.repeat(70));
    console.log('🛡️  SECURITY SUMMARY & NEXT ACTIONS');
    console.log('═'.repeat(70));
    
    if (maliciousPackages.length > 0) {
      console.log('\n🚨 IMMEDIATE THREAT - MALICIOUS PACKAGES DETECTED');
      console.log('\nWHAT THIS MEANS:');
      console.log('   Your system may be compromised. These packages can steal data,');
      console.log('   install backdoors, or perform other malicious activities.');
      
      console.log('\nACTIONS TO TAKE RIGHT NOW:');
      console.log('   1. 🛑 Stop all running Node.js applications');
      console.log('   2. 🗑️  Remove malicious packages immediately:');
      for (const pkg of maliciousPackages.slice(0, 3)) {
        console.log(`      rm -rf "${pkg.path}"`);
      }
      console.log('   3. 🧹 Clean installation:');
      console.log('      rm -rf node_modules package-lock.json');
      console.log('      npm cache clean --force');
      console.log('      npm install');
      console.log('   4. 🔍 Scan your system for other compromises');
      console.log('   5. 🔐 Change any passwords/tokens that may have been exposed');
    }
    
    const criticalRisks = risks.filter(r => r.severity === 'critical');
    const highRisks = risks.filter(r => r.severity === 'high');
    
    if (criticalRisks.length > 0) {
      console.log('\n🔴 CRITICAL SECURITY ISSUES');
      console.log('\nWHAT THIS MEANS:');
      console.log('   These issues could lead to immediate security breaches.');
      
      console.log('\nFIX THESE NOW:');
      let actionNum = 1;
      for (const risk of criticalRisks.slice(0, 3)) {
        console.log(`   ${actionNum}. ${this.getActionableRecommendation(risk)}`);
        actionNum++;
      }
      if (criticalRisks.length > 3) {
        console.log(`   ... ${criticalRisks.length - 3} more critical issues (use -v for details)`);
      }
    }
    
    if (highRisks.length > 0) {
      console.log('\n🟠 HIGH PRIORITY ISSUES');
      console.log('\nWHAT THIS MEANS:');
      console.log('   These could become security problems soon or under certain conditions.');
      
      console.log('\nFIX THESE SOON:');
      for (const risk of highRisks.slice(0, 2)) {
        console.log(`   • ${this.getActionableRecommendation(risk)}`);
      }
      if (highRisks.length > 2) {
        console.log(`   ... ${highRisks.length - 2} more high priority issues (use -v for details)`);
      }
    }
    
    const mediumLowCount = risks.length - criticalRisks.length - highRisks.length;
    if (mediumLowCount > 0) {
      console.log(`\n📋 ${mediumLowCount} additional medium/low priority improvements available`);
      console.log('   Run with -v flag to see all recommendations');
    }
    
    console.log('\n💡 PREVENTION TIPS:');
    console.log('   • Run this scanner in your CI/CD pipeline');
    console.log('   • Use exact version pinning for critical packages');
    console.log('   • Never commit .env files or auth tokens');
    console.log('   • Keep your package managers updated');
    console.log('   • Regularly run npm audit');
  }
  
  getActionableRecommendation(risk) {
    switch (risk.type) {
      case 'vulnerable-range':
        return `Pin ${risk.package} to safe version (change "${risk.currentRange}" to exact version, NOT ${risk.maliciousVersion})`;
      case 'no-lock-file':
        return 'Create lock file: run "npm install" or "yarn install"';
      case 'exposed-auth-token':
        const gitAdvice = risk.gitIgnored ? '' : ' Add .npmrc to .gitignore.';
        return `Remove auth token from ${path.basename(risk.file)}, use environment variable instead.${gitAdvice}`;
      case 'insecure-registry':
        return 'Change registry to HTTPS: npm config set registry https://registry.npmjs.org/';
      case 'insecure-global-registry':
        return 'Change global registry to HTTPS: npm config set registry https://registry.npmjs.org/';
      case 'global-tls-disabled':
        return 'Enable SSL globally: npm config set strict-ssl true';
      case 'tls-disabled':
        return 'Remove NODE_TLS_REJECT_UNAUTHORIZED=0 environment variable';
      case 'dangerous-script':
        return `Review and secure the "${risk.script}" script - it contains dangerous commands`;
      case 'multiple-lock-files':
        return `Keep only one lock file - delete ${risk.files.slice(1).join(', ')}`;
      case 'suspicious-registry-in-lock':
        return `Verify this registry is legitimate or delete lock file and reinstall: rm ${risk.lockFile} && npm install`;
      case 'insecure-configured-registry':
        return `Switch to HTTPS version of your registry or use: npm config set registry https://your-secure-registry.com`;
      case 'no-integrity-hashes':
        return 'Update npm and regenerate lock file: npm install -g npm@latest && rm package-lock.json && npm install';
      case 'invalid-lock-file':
        return `Delete and regenerate lock file: rm ${risk.lockFile} && npm install`;
      default:
        return risk.recommendation;
    }
  }

  printScanStats(summary, options) {
    console.log(`\n⏱️  Comprehensive scan completed in ${summary.scanTime}ms`);
    
    const logEntries = this.logger.getEntries();
    const nodeModulesFound = logEntries.filter(e => 
      e.message.includes('Found node_modules') || 
      e.message.includes('Found nested')
    ).length;
    
    const packagesChecked = logEntries.filter(e => 
      e.message.includes('Checking package') || 
      e.message.includes('Checking global')
    ).length;
    
    console.log('📊 SCAN COVERAGE:');
    console.log(`   📁 node_modules directories: ${nodeModulesFound}`);
    console.log(`   📦 Packages examined: ${packagesChecked}`);
    console.log(`   🌍 Global packages: checked`);
    console.log(`   💾 Package caches: scanned (npm, yarn, pnpm)`);
    console.log(`   📋 Configuration files: analyzed`);
    console.log(`   🔍 Nested dependencies: deep scan performed`);
    console.log(`   🛡️ Security risks: comprehensive analysis`);
    
    if (options.verbose) {
      console.log('\n' + '─'.repeat(60));
      console.log('DETAILED SCAN LOG:');
      console.log('─'.repeat(60));
      this.logger.printDetailedLog();
    }
  }

  printDetailedAnalysis(risks) {
    console.log('\n' + '─'.repeat(60));
    console.log('DETAILED SECURITY ANALYSIS:');
    console.log('─'.repeat(60));
    
    const risksByType = this.groupRisksByType(risks);
    
    for (const [type, typeRisks] of Object.entries(risksByType)) {
      console.log(`\n📋 ${type.toUpperCase().replace(/-/g, ' ')}:`);
      
      for (const risk of typeRisks) {
        const severity = this.getSeverityIcon(risk.severity);
        console.log(`   ${severity} ${risk.message}`);
        
        if (risk.recommendation) {
          console.log(`      💡 ${risk.recommendation}`);
        }
        
        // Mostrar detalles específicos
        this.printRiskDetails(risk);
      }
    }
  }

  groupRisksByType(risks) {
    const byType = {};
    for (const risk of risks) {
      if (!byType[risk.type]) byType[risk.type] = [];
      byType[risk.type].push(risk);
    }
    return byType;
  }

  getSeverityIcon(severity) {
    const icons = {
      critical: '🚨',
      high: '🔴',
      medium: '🟡',
      low: '🔵'
    };
    return icons[severity] || '•';
  }

  printRiskDetails(risk) {
    const details = [];
    
    if (risk.package) details.push(`Package: ${risk.package}`);
    if (risk.currentRange) details.push(`Range: ${risk.currentRange}`);
    if (risk.maliciousVersion) details.push(`Malicious: ${risk.maliciousVersion}`);
    if (risk.file) details.push(`File: ${risk.file}`);
    if (risk.script) details.push(`Script: ${risk.script}`);
    if (risk.registry) details.push(`Registry: ${risk.registry}`);
    if (risk.variable) details.push(`Variable: ${risk.variable}`);
    
    for (const detail of details) {
      console.log(`         ${detail}`);
    }
  }

  saveDetailedReport(filename, summary, maliciousPackages, risks, cacheResults) {
    const report = {
      timestamp: new Date().toISOString(),
      summary,
      maliciousPackages,
      cacheResults,
      risks: this.categorizeRisks(risks),
      detailedLog: this.logger.getEntries(),
      recommendations: this.generateActionPlan(risks, maliciousPackages),
      metadata: {
        scanner: 'is-my-code-pwned',
        version: '2.0.0',
        nodeVersion: process.version,
        platform: process.platform
      }
    };
    
    try {
      fs.writeFileSync(filename, JSON.stringify(report, null, 2));
      this.logger.info(`Security report saved to ${filename}`);
    } catch (error) {
      console.error(`Failed to save report: ${error.message}`);
    }
  }

  categorizeRisks(risks) {
    return {
      critical: risks.filter(r => r.severity === 'critical'),
      high: risks.filter(r => r.severity === 'high'),
      medium: risks.filter(r => r.severity === 'medium'),
      low: risks.filter(r => r.severity === 'low')
    };
  }

  generateActionPlan(risks, maliciousPackages) {
    const actions = [];
    
    // Acciones inmediatas para paquetes maliciosos
    if (maliciousPackages.length > 0) {
      actions.push({
        priority: 'IMMEDIATE',
        category: 'Malicious Package Removal',
        actions: [
          'Stop all running applications',
          'Remove malicious packages immediately',
          'Delete node_modules directory',
          'Clear package manager caches',
          'Reinstall dependencies from clean state',
          'Scan system for signs of compromise'
        ]
      });
    }
    
    // Acciones para riesgos críticos
    const criticalRisks = risks.filter(r => r.severity === 'critical');
    if (criticalRisks.length > 0) {
      const criticalActions = criticalRisks.map(risk => risk.recommendation);
      actions.push({
        priority: 'URGENT',
        category: 'Critical Security Fixes',
        actions: [...new Set(criticalActions)]
      });
    }
    
    // Acciones para riesgos altos
    const highRisks = risks.filter(r => r.severity === 'high');
    if (highRisks.length > 0) {
      const highActions = highRisks.map(risk => risk.recommendation);
      actions.push({
        priority: 'HIGH',
        category: 'High Priority Security Improvements',
        actions: [...new Set(highActions)]
      });
    }
    
    // Mejores prácticas generales
    actions.push({
      priority: 'ONGOING',
      category: 'Security Best Practices',
      actions: [
        'Implement automated security scanning in CI/CD',
        'Regularly update dependencies',
        'Use exact version pinning for critical packages',
        'Enable npm audit in automated checks',
        'Implement code signing for internal packages',
        'Regular security training for development team'
      ]
    });
    
    return actions;
  }

  printJsonOutput(summary, maliciousPackages, risks, cacheResults) {
    const output = {
      ...summary,
      maliciousPackages,
      cacheResults,
      risks: this.categorizeRisks(risks),
      detailedLog: this.logger.getEntries()
    };
    
    console.log(JSON.stringify(output, null, 2));
  }
}

module.exports = SecurityReporter;