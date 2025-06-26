// detectionSignature.ts - Optimized signature-based detection for Certification Authority APIs

import {
	filePath,
	LogEntry,
	DetectionResult,
	FilePosition,
	initializeCSV,
	readNewCSVLogEntries,
	logDetectionResult,
} from '../utils';
import { securityPatterns } from './security-patterns';
// Signature-based Detection Implementation
export class SignatureBasedDetection {
	private static readonly KNOWN_ATTACK_PATTERNS = securityPatterns;

	detect(entry: LogEntry): DetectionResult {
		try {
			// Convert entire request and response objects to strings for pattern matching
			const reqStr = JSON.stringify(entry.request);
			const resStr = JSON.stringify(entry.response);
			const combinedStr = reqStr + resStr;

			// Check against each pattern category
			for (const [category, patterns] of Object.entries(SignatureBasedDetection.KNOWN_ATTACK_PATTERNS)) {
				for (const pattern of patterns as RegExp[]) {
					if (pattern.test(combinedStr)) {
						return {
							detected: true,
							reason: `Signature match: ${category} pattern detected: ${pattern}`,
						};
					}
				}
			}

			return {
				detected: false,
				reason: 'No known attack signatures detected',
			};
		} catch (error) {
			console.error('Error in signature detection:', error);
			return {
				detected: false,
				reason: `Error during detection: ${error instanceof Error ? error.message : String(error)}`,
			};
		}
	}
}

// Main Detection Function
async function detectIntrusions(entry: LogEntry): Promise<void> {
	try {
		// Start timing for overall request processing
		const requestStartTime = performance.now();

		const detector = new SignatureBasedDetection();
		const result = detector.detect(entry);

		const requestEndTime = performance.now();
		const totalRequestDuration = requestEndTime - requestStartTime;

		await logDetectionResult(entry, 'signature', result);

		console.log(`########## Signature Detection Processing Time: ${totalRequestDuration.toFixed(10)}ms ##########`);
		if (result.detected) {
			console.log('⚠️ SIGNATURE-BASED INTRUSION DETECTED ⚠️');
			console.log(`Reason: ${result.reason}`);
		} else {
			console.log('✅ No attack signatures detected');
		}
	} catch (error) {
		console.error('Error in intrusion detection:', error);
	}
}

// Main Function to Start Detection
export async function startSignatureDetection(logFilePath: string) {
	try {
		await initializeCSV(filePath('/public/signature_detection_logs.csv'), 'detection');
		const filePosition = new FilePosition();

		// First, read the entire file initially to catch up
		console.log('Initial reading of the log file...');
		const initialEntries = await readNewCSVLogEntries(logFilePath, filePosition);

		if (initialEntries.length > 0) {
			console.log(`Processing ${initialEntries.length} existing entries from CSV...`);

			// Process a batch of entries at a time to avoid overwhelming the system
			const batchSize = 10;
			for (let i = 0; i < initialEntries.length; i += batchSize) {
				const batch = initialEntries.slice(i, i + batchSize);
				console.log(`Processing batch ${i / batchSize + 1}/${Math.ceil(initialEntries.length / batchSize)}`);

				for (const entry of batch) {
					await detectIntrusions(entry);
				}
			}
		} else {
			console.log('No existing entries found in the log file.');
		}

		return 'done';

		// const runDetectionCycle = async () => {
		// 	try {
		// 		const newEntries = await readNewCSVLogEntries(logFilePath, filePosition);

		// 		if (newEntries.length > 0) {
		// 			console.log(`Processing ${newEntries.length} new entries from CSV...`);

		// 			for (const entry of newEntries) {
		// 				await detectIntrusions(entry);
		// 			}
		// 		}
		// 	} catch (error) {
		// 		console.error('Error in detection cycle:', error);
		// 	}
		// };
		// runDetectionCycle();
	} catch (error) {
		console.error('Error starting detection:', error);
		return 'error';
	}
}
