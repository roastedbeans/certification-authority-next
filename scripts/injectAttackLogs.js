/**
 * Inject Attack Logs Utility
 *
 * This script injects generated attack logs into the main CA formatted logs file
 * to allow testing of rate limit detection and other security features.
 */

const fs = require('fs');
const path = require('path');

// Path to the log files
const ATTACK_LOGS_PATH = path.join(process.cwd(), 'public', 'attack_formatted_logs.csv');
const CA_LOGS_PATH = path.join(process.cwd(), 'public', 'ca_formatted_logs.csv');
const CA_LOGS_BACKUP_PATH = path.join(process.cwd(), 'public', 'ca_formatted_logs_backup.csv');

/**
 * Injects attack logs into the CA logs file
 * @param {string} mode - Either 'append' to add logs at the end or 'blend' to mix them throughout
 */
function injectLogs(mode = 'append') {
	console.log(`Starting log injection in '${mode}' mode...`);

	try {
		// Check if attack logs exist
		if (!fs.existsSync(ATTACK_LOGS_PATH)) {
			console.error('Attack logs not found. Please run apiRateLimitAttacker.js first.');
			process.exit(1);
		}

		// Check if CA logs exist
		if (!fs.existsSync(CA_LOGS_PATH)) {
			console.error('CA logs not found. Please make sure ca_formatted_logs.csv exists in the public directory.');
			process.exit(1);
		}

		// Create backup of original logs
		fs.copyFileSync(CA_LOGS_PATH, CA_LOGS_BACKUP_PATH);
		console.log(`Original logs backed up to ${CA_LOGS_BACKUP_PATH}`);

		// Read logs
		const attackLogs = fs.readFileSync(ATTACK_LOGS_PATH, 'utf8').split('\n');
		const caLogs = fs.readFileSync(CA_LOGS_PATH, 'utf8').split('\n');

		// Extract headers
		const attackHeader = attackLogs[0];
		const caHeader = caLogs[0];

		// Get data lines
		const attackLines = attackLogs.slice(1).filter((line) => line.trim() !== '');
		const caLines = caLogs.slice(1).filter((line) => line.trim() !== '');

		let resultLines = [];

		if (mode === 'append') {
			// Simply append attack logs to the end of CA logs
			resultLines = [caHeader, ...caLines, ...attackLines];
		} else if (mode === 'blend') {
			// Blend attack logs throughout the CA logs
			resultLines = [caHeader];

			// If no CA logs, just use attack logs
			if (caLines.length === 0) {
				resultLines.push(...attackLines);
			} else {
				// Calculate insertion points
				const totalAttackLines = attackLines.length;
				const interval = Math.max(1, Math.floor(caLines.length / totalAttackLines));

				// Insert attack logs at intervals
				let attackIndex = 0;
				for (let i = 0; i < caLines.length; i++) {
					resultLines.push(caLines[i]);

					// Insert an attack log at regular intervals
					if (i % interval === 0 && attackIndex < attackLines.length) {
						resultLines.push(attackLines[attackIndex]);
						attackIndex++;
					}
				}

				// Add any remaining attack logs at the end
				if (attackIndex < attackLines.length) {
					resultLines.push(...attackLines.slice(attackIndex));
				}
			}
		} else {
			console.error(`Unknown mode: ${mode}. Use 'append' or 'blend'.`);
			process.exit(1);
		}

		// Write back to CA logs file
		fs.writeFileSync(CA_LOGS_PATH, resultLines.join('\n'));

		console.log(`
Log Injection Complete
---------------------
Original log entries: ${caLines.length}
Attack log entries:   ${attackLines.length}
Total log entries:    ${resultLines.length - 1}  // Subtract 1 for header
CA logs file:         ${CA_LOGS_PATH}
Backup file:          ${CA_LOGS_BACKUP_PATH}
`);

		console.log('You can now run rate limit detection to analyze the injected logs.');
	} catch (error) {
		console.error('Error injecting logs:', error);
		process.exit(1);
	}
}

/**
 * Restores the original CA logs from backup
 */
function restoreLogs() {
	try {
		if (fs.existsSync(CA_LOGS_BACKUP_PATH)) {
			fs.copyFileSync(CA_LOGS_BACKUP_PATH, CA_LOGS_PATH);
			console.log(`Original logs restored from ${CA_LOGS_BACKUP_PATH}`);
		} else {
			console.error('Backup file not found. Cannot restore logs.');
		}
	} catch (error) {
		console.error('Error restoring logs:', error);
	}
}

// Parse command line arguments
function parseArgs() {
	const args = process.argv.slice(2);
	const action = args[0] || 'inject';
	const mode = args[1] || 'append';

	return { action, mode };
}

// Print help message
function showHelp() {
	console.log(`
Inject Attack Logs Utility
-------------------------
This tool injects generated attack logs into the CA formatted logs for testing.

Usage:
  node injectAttackLogs.js [action] [mode]

Actions:
  inject   - Inject attack logs (default)
  restore  - Restore original logs from backup
  help     - Show this help message

Modes (for inject action):
  append   - Append attack logs to the end of CA logs (default)
  blend    - Blend attack logs throughout the CA logs

Examples:
  # Inject attack logs by appending them at the end
  node injectAttackLogs.js inject append

  # Inject attack logs by blending them throughout
  node injectAttackLogs.js inject blend

  # Restore original logs from backup
  node injectAttackLogs.js restore
`);
}

// Main function
function main() {
	const { action, mode } = parseArgs();

	if (action === 'help') {
		showHelp();
	} else if (action === 'inject') {
		injectLogs(mode);
	} else if (action === 'restore') {
		restoreLogs();
	} else {
		console.error(`Unknown action: ${action}`);
		showHelp();
	}
}

// Run the main function
main();
