class Logger {
  constructor() {
    this.entries = [];
    this.currentPath = '';
  }

  setCurrentPath(path) {
    this.currentPath = path;
  }

  log(level, message, details = null) {
    this.entries.push({
      timestamp: new Date().toISOString(),
      level,
      message,
      details,
      path: this.currentPath
    });
  }

  critical(message, details) {
    this.log('critical', message, details);
  }

  error(message, details) {
    this.log('error', message, details);
  }

  warning(message, details) {
    this.log('warning', message, details);
  }

  info(message, details) {
    this.log('info', message, details);
  }

  debug(message, details) {
    this.log('debug', message, details);
  }

  getEntries() {
    return this.entries;
  }

  clear() {
    this.entries = [];
  }

  printDetailedLog() {
    const logLevels = {
      'critical': '🚨',
      'error': '❌',
      'warning': '⚠️ ',
      'info': 'ℹ️ ',
      'debug': '🔍'
    };
    
    for (const entry of this.entries) {
      const icon = logLevels[entry.level] || '•';
      const time = entry.timestamp.substring(11, 19);
      console.log(`${icon} [${time}] ${entry.message}`);
      if (entry.details && Object.keys(entry.details).length > 0) {
        for (const [key, value] of Object.entries(entry.details)) {
          console.log(`    ${key}: ${value}`);
        }
      }
    }
  }
}

module.exports = Logger;