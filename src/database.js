const fs = require('fs');
const path = require('path');

class MaliciousPackageDatabase {
  constructor() {
    this.packages = {};
    this.loadDatabase();
  }

  loadDatabase() {
    try {
      const dbPath = path.join(__dirname, '..', 'malicious-packages.json');
      const data = fs.readFileSync(dbPath, 'utf8');
      this.packages = JSON.parse(data);
    } catch (error) {
      console.error('Error loading malicious packages database:', error.message);
      process.exit(1);
    }
  }

  isMalicious(packageName, version) {
    return this.packages[packageName] === version;
  }

  getMaliciousVersion(packageName) {
    return this.packages[packageName] || null;
  }

  getAllPackageNames() {
    return Object.keys(this.packages);
  }

  getPackageCount() {
    return Object.keys(this.packages).length;
  }
}

module.exports = MaliciousPackageDatabase;