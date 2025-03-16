/**
 * Timeframe Data Fixer
 *
 * This script fixes issues with existing timeframe analysis data,
 * such as random endpoint IDs or other inconsistencies.
 */

const fs = require('fs');
const path = require('path');

// Path to the timeframe analysis file
const TIMEFRAME_FILE = path.join(process.cwd(), 'public', 'rate_limit_timeframe_analysis.csv');
const FIXED_FILE = path.join(process.cwd(), 'public', 'rate_limit_timeframe_analysis_fixed.csv');

/**
 * Fixes common issues in timeframe analysis data
 */
function fixTimeframeData() {
	console.log('Fixing timeframe analysis data...');

	try {
		// Check if file exists
		if (!fs.existsSync(TIMEFRAME_FILE)) {
			console.error('Timeframe analysis file not found.');
			return;
		}

		// Read existing data
		const content = fs.readFileSync(TIMEFRAME_FILE, 'utf8');
		const lines = content.split('\n');

		// Get header and data lines
		const header = lines[0];
		const dataLines = lines.slice(1).filter((line) => line.trim() !== '');

		// Initialize output with header
		const outputLines = [header];

		// Count of issues fixed
		let randomEndpointCount = 0;
		let emptyEndpointCount = 0;
		let otherFixCount = 0;

		// Process each line
		dataLines.forEach((line) => {
			const parts = line.split(',');

			// Check number of fields to ensure we're working with valid data
			if (parts.length < 7) {
				// Just copy malformed lines without changes
				outputLines.push(line);
				return;
			}

			// Extract fields (assuming CSV format from the timeframe analysis)
			// Format: startTime,endTime,isAnomaly,reason,requestCount,clientId,endpoint
			const [startTime, endTime, isAnomaly, reason, requestCount, clientId, endpoint] = parts;

			// Fix endpoint issues
			let fixedEndpoint = endpoint;

			// Check for random unknown values (unknown-xxxx)
			if (endpoint.startsWith('unknown-') && endpoint !== 'unknown-endpoint') {
				fixedEndpoint = 'unknown-endpoint';
				randomEndpointCount++;
			}

			// Check for empty endpoints
			if (!endpoint.trim()) {
				fixedEndpoint = 'unknown-endpoint';
				emptyEndpointCount++;
			}

			// Fix other specific endpoints if needed
			if (endpoint === 'unknown-qiwdaisj') {
				fixedEndpoint = 'unknown-endpoint';
				otherFixCount++;
			}

			// Construct fixed line
			const fixedLine = `${startTime},${endTime},${isAnomaly},${reason},${requestCount},${clientId},${fixedEndpoint}`;
			outputLines.push(fixedLine);
		});

		// Write fixed data to new file
		fs.writeFileSync(FIXED_FILE, outputLines.join('\n'));

		// Report results
		console.log(`
Timeframe Data Fix Complete
---------------------------
Original file: ${TIMEFRAME_FILE}
Fixed file: ${FIXED_FILE}
Total entries: ${dataLines.length}
Random endpoints fixed: ${randomEndpointCount}
Empty endpoints fixed: ${emptyEndpointCount}
Other specific fixes: ${otherFixCount}
Total fixes: ${randomEndpointCount + emptyEndpointCount + otherFixCount}
`);

		if (randomEndpointCount + emptyEndpointCount + otherFixCount > 0) {
			console.log(`
To use the fixed data, you can manually copy the fixed file over the original:
cp "${FIXED_FILE}" "${TIMEFRAME_FILE}"
`);
		} else {
			console.log('No issues were found in the timeframe data.');
		}
	} catch (error) {
		console.error('Error fixing timeframe data:', error);
	}
}

/**
 * Command line interface
 */
function main() {
	const args = process.argv.slice(2);

	if (args.includes('--help') || args.includes('-h')) {
		console.log(`
Timeframe Data Fixer
-------------------
This utility fixes issues in timeframe analysis data.

Usage:
  node fixTimeframeData.js [options]

Options:
  --help, -h   Show this help message
  --apply      Apply fixes directly to the original file
                (creates a backup of the original file first)

Example:
  node fixTimeframeData.js --apply
`);
		return;
	}

	// Fix the data
	fixTimeframeData();

	// If --apply flag is present, copy the fixed file over the original
	if (args.includes('--apply')) {
		try {
			const backupFile = `${TIMEFRAME_FILE}.bak`;

			// Create backup
			fs.copyFileSync(TIMEFRAME_FILE, backupFile);
			console.log(`Original file backed up to: ${backupFile}`);

			// Apply fix
			fs.copyFileSync(FIXED_FILE, TIMEFRAME_FILE);
			console.log(`Fixes applied to original file: ${TIMEFRAME_FILE}`);
		} catch (error) {
			console.error('Error applying fixes:', error);
		}
	}
}

// Run the main function
main();
