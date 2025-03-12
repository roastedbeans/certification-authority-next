#!/usr/bin/env node

/**
 * Run Rate Limit Detection Script
 *
 * This is a simple wrapper script to run the rate limit detection system.
 * It simplifies the command to analyze API logs for rate limit violations.
 *
 * Usage: node runRateLimitDetection.js [logFilePath]
 */

const path = require('path');
const { spawn } = require('child_process');

// The log file path to analyze (default or from command line argument)
const logFilePath = process.argv[2] || path.join(process.cwd(), 'public', 'requests_responses.txt');

console.log('======================================');
console.log('Rate Limit Detection System');
console.log('======================================');
console.log(`Analyzing log file: ${logFilePath}`);
console.log('--------------------------------------');

// Use ts-node to run the TypeScript detector with the combined file
const detector = spawn('npx', ['ts-node', 'scripts/rateLimitAll.ts', logFilePath], {
	stdio: 'inherit',
	shell: true,
});

detector.on('close', (code) => {
	console.log('--------------------------------------');
	if (code === 0) {
		console.log('Rate limit analysis completed successfully');
	} else {
		console.error(`Rate limit analysis failed with code ${code}`);
	}
	console.log('======================================');
});
