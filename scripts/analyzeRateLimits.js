#!/usr/bin/env node

/**
 * Rate Limit Analysis Script
 *
 * This script executes the sliding window rate limit analysis on the request logs file.
 * It reads the requests_responses.txt file and applies the rate limiting algorithm to
 * identify potential violations.
 *
 * Usage: node analyzeRateLimits.js [logFilePath]
 */

const { analyzeLogsWithRateLimit } = require('./slidingWindowRateLimit');
const path = require('path');

// Default log file path
const DEFAULT_LOG_PATH = path.join(process.cwd(), 'public', 'requests_responses.txt');

// Get log file path from command line arguments or use default
const logFilePath = process.argv[2] || DEFAULT_LOG_PATH;

console.log(`Starting rate limit analysis on: ${logFilePath}`);

// Run the analysis
analyzeLogsWithRateLimit(logFilePath)
	.then(() => {
		console.log('Rate limit analysis completed successfully.');
	})
	.catch((error) => {
		console.error('Error during rate limit analysis:', error);
		process.exit(1);
	});
