'use server';

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { startSpecificationDetection } from '@/scripts/detectionSpecification';
import { filePath } from '@/scripts/utils';
import { startHybridDetection } from '@/scripts/detectionHybrid';
import { startSignatureDetection } from '@/scripts/detectionSignature';
import { analyzeSecurityLogs } from '@/scripts/runAnalysis';
import { startRateLimitDetection } from '@/scripts/slidingWindowRateLimit';

const execPromise = promisify(exec);

// Path helpers
const publicPath = path.join(process.cwd(), 'public');
const logsPath = path.join(process.cwd(), 'logs');
const scriptsPath = path.join(process.cwd(), 'scripts');

// Ensure directories exist
async function ensureDirectories() {
	try {
		await fs.mkdir(publicPath, { recursive: true });
		await fs.mkdir(logsPath, { recursive: true });
	} catch (error) {
		console.error('Error ensuring directories exist:', error);
	}
}

// Call once when server starts
ensureDirectories();

export interface DetectionResult {
	success: boolean;
	message: string;
	data?: any;
	error?: string;
}

export interface LogEntry {
	timestamp: string;
	detectionType: string;
	detected: boolean | string;
	reason: string;
	request: string;
	response: string;
}

export async function runSignatureDetection(): Promise<DetectionResult> {
	const data = await startSignatureDetection(filePath('/public/ca_formatted_logs.csv'));

	if (data === 'done') {
		return {
			success: true,
			message: 'Signature-based detection completed successfully, please check the logs in Log Viewer for more details',
			data: data,
		};
	} else {
		return {
			success: false,
			message: 'Signature-based detection failed',
			error: data,
		};
	}
}

export async function runSpecificationDetection(): Promise<DetectionResult> {
	const data = await startSpecificationDetection(filePath('/public/ca_formatted_logs.csv'));

	if (data === 'done') {
		return {
			success: true,
			message:
				'Specification-based detection completed successfully, please check the logs in Log Viewer for more details',
			data: data,
		};
	} else {
		return {
			success: false,
			message: 'Specification-based detection failed',
			error: data,
		};
	}
}

export async function runHybridDetection(): Promise<DetectionResult> {
	// Run with a timeout to prevent hanging
	const data = await startHybridDetection(filePath('/public/ca_formatted_logs.csv'));

	if (data === 'done') {
		return {
			success: true,
			message: 'Hybrid detection completed successfully, please check the logs in Log Viewer for more details',
			data: data,
		};
	} else {
		return {
			success: false,
			message: 'Hybrid detection failed',
			error: data,
		};
	}
}

export async function runAnalysis(): Promise<DetectionResult> {
	const summary = await analyzeSecurityLogs();

	if (summary) {
		return {
			success: true,
			message: 'Analysis completed successfully',
			data: summary,
		};
	} else {
		return {
			success: false,
			message: 'Analysis failed',
		};
	}
}

export async function runRateLimitDetection(): Promise<DetectionResult> {
	try {
		// Run sliding window rate limit detection
		const data = await startRateLimitDetection();

		if (data === 'done') {
			return {
				success: true,
				message: 'Rate limit detection completed successfully, please check the logs in Log Viewer for more details',
				data: data,
			};
		} else {
			return {
				success: false,
				message: 'Rate limit detection failed',
				error: data,
			};
		}
	} catch (error: any) {
		console.error('Error running rate limit detection:', error);
		return {
			success: false,
			message: 'Rate limit detection failed',
			error: error.message,
		};
	}
}

export async function getDetectionLogs(
	type: 'signature' | 'specification' | 'hybrid' | 'ratelimit' | 'all'
): Promise<{ logs: LogEntry[]; error?: string }> {
	try {
		let allLogs: LogEntry[] = [];
		let lastModified = new Map<string, Date>();

		if (type === 'signature' || type === 'all') {
			const signatureFile = path.join(publicPath, 'signature_detection_logs.csv');
			if (await hasFileChanged(signatureFile, lastModified)) {
				const signatureLogs = await readCsvLogFile(signatureFile);
				allLogs = [...allLogs, ...signatureLogs];
			}
		}

		if (type === 'specification' || type === 'all') {
			const specFile = path.join(publicPath, 'specification_detection_logs.csv');
			if (await hasFileChanged(specFile, lastModified)) {
				const specificationLogs = await readCsvLogFile(specFile);

				allLogs = [...allLogs, ...specificationLogs];
			}
		}

		if (type === 'hybrid' || type === 'all') {
			const hybridFile = path.join(publicPath, 'hybrid_detection_logs.csv');
			if (await hasFileChanged(hybridFile, lastModified)) {
				const hybridLogs = await readCsvLogFile(hybridFile);
				allLogs = [...allLogs, ...hybridLogs];
			}
		}

		if (type === 'ratelimit' || type === 'all') {
			const rateLimitFile = path.join(publicPath, 'rate_limit_detection_logs.csv');
			if (await hasFileChanged(rateLimitFile, lastModified)) {
				const rateLimitLogs = await readCsvLogFile(rateLimitFile);
				allLogs = [...allLogs, ...rateLimitLogs];
			}
		}

		// Sort logs by timestamp, newest first
		allLogs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

		return { logs: allLogs };
	} catch (error: any) {
		return {
			logs: [],
			error: error.message,
		};
	}
}

async function readCsvLogFile(filePath: string): Promise<LogEntry[]> {
	try {
		const fileContent = await fs.readFile(filePath, 'utf-8');
		const lines = fileContent.split('\n');
		const headers = lines[0].split(',');

		console.log('headers', headers);
		return lines
			.slice(1)
			.filter((line) => line.trim() !== '')
			.map((line) => {
				// Handle values inside curly braces to prevent splitting them
				const processedLine = line.replace(/{[^}]*}/g, (match) => match.replace(/,/g, '##COMMA##'));
				const values = processedLine.split(',').map((val) => val.replace(/##COMMA##/g, ','));

				const entry: any = {};

				headers.forEach((header, index) => {
					let value = values[index] || '';
					entry[header] = value;
				});

				// Convert detected field to proper type after all fields are set
				if (typeof entry.detected === 'string') {
					entry.detected = entry.detected === 'true' ? true : entry.detected === 'false' ? false : entry.detected;
				}

				return entry as LogEntry;
			});
	} catch (error) {
		// If file doesn't exist, return empty array
		return [];
	}
}

export async function getApiLogsSummary(): Promise<{
	total: number;
	attacks: number;
	signatureDetections: number;
	specificationDetections: number;
	hybridDetections: number;
	rateLimitDetections: number;
}> {
	try {
		const lastModified = new Map<string, Date>();
		// Check if files have changed before reading
		const signatureFile = path.join(publicPath, 'signature_detection_logs.csv');
		const specificationFile = path.join(publicPath, 'specification_detection_logs.csv');
		const hybridFile = path.join(publicPath, 'hybrid_detection_logs.csv');
		const rateLimitFile = path.join(publicPath, 'rate_limit_detection_logs.csv');
		const caFile = path.join(publicPath, 'ca_formatted_logs.csv');

		const [signatureChanged, specificationChanged, hybridChanged, rateLimitChanged, caChanged] = await Promise.all([
			hasFileChanged(signatureFile, lastModified),
			hasFileChanged(specificationFile, lastModified),
			hasFileChanged(hybridFile, lastModified),
			hasFileChanged(rateLimitFile, lastModified),
			hasFileChanged(caFile, lastModified),
		]);

		// Only read files that have changed
		const [signatureLogs, specificationLogs, hybridLogs, rateLimitLogs, caLogs] = await Promise.all([
			signatureChanged ? readCsvLogFile(signatureFile) : [],
			specificationChanged ? readCsvLogFile(specificationFile) : [],
			hybridChanged ? readCsvLogFile(hybridFile) : [],
			rateLimitChanged ? readCsvLogFile(rateLimitFile) : [],
			caChanged ? readCsvLogFile(caFile) : [],
		]);

		// Calculate counts
		const total = caLogs.length;
		const attacks = caLogs.filter((log: any) => log['attack.type'] && log['attack.type'] !== '').length;
		const signatureDetections = signatureLogs.filter((log) => log.detected !== false).length;
		const specificationDetections = specificationLogs.filter((log) => log.detected !== false).length;
		const hybridDetections = hybridLogs.filter((log) => log.detected !== false).length;
		const rateLimitDetections = rateLimitLogs.filter((log) => log.detected !== false).length;

		return {
			total,
			attacks,
			signatureDetections,
			specificationDetections,
			hybridDetections,
			rateLimitDetections,
		};
	} catch (error) {
		// Return default values if anything fails
		return {
			total: 0,
			attacks: 0,
			signatureDetections: 0,
			specificationDetections: 0,
			hybridDetections: 0,
			rateLimitDetections: 0,
		};
	}
}

// Helper to check if file has changed
const hasFileChanged = async (filePath: string, lastModified: Map<string, Date>): Promise<boolean> => {
	try {
		const stats = await fs.stat(filePath);
		const currentModified = stats.mtime;
		const previousModified = lastModified.get(filePath);

		if (!previousModified || currentModified > previousModified) {
			lastModified.set(filePath, currentModified);
			return true;
		}
		return false;
	} catch {
		return true; // If error reading stats, assume changed
	}
};
