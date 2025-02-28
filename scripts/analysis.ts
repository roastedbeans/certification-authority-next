import fs from 'fs';
import path from 'path';
import Papa from 'papaparse';

const filePath = (pathString: string) => {
	return path.join(process.cwd(), pathString);
};

interface LogRecord {
	index?: number;
	timestamp: string;
	detectionType: 'Signature' | 'Specification' | 'Hybrid';
	detected: boolean | string;
	reason: string;
	request: string;
	response: string;
}

interface LogData {
	[key: string]: string;
	'attack.type': string;
	'request.method': string;
	'request.url': string;
	'response.status': string;
}

interface ConfusionMatrix {
	truePositive: number;
	falsePositive: number;
	trueNegative: number;
	falseNegative: number;
}

class LogMonitor {
	private logs: LogData[] = [];
	private specificationLogs: LogRecord[] = [];
	private signatureLogs: LogRecord[] = [];
	private hybridLogs: LogRecord[] = [];

	private readonly logPath: string;
	private readonly specificationLogPath: string;
	private readonly signatureLogPath: string;
	private readonly hybridLogPath: string;
	private readonly maxRecords: number;

	constructor(
		logPath: string = filePath('/public/ca_formatted_logs.csv'),
		specificationLogPath: string = filePath('/public/specification_detection_logs.csv'),
		signatureLogPath: string = filePath('/public/signature_detection_logs.csv'),
		hybridLogPath: string = filePath('/public/hybrid_detection_logs.csv'),
		maxRecords: number = 10000
	) {
		this.logPath = logPath;
		this.specificationLogPath = specificationLogPath;
		this.signatureLogPath = signatureLogPath;
		this.hybridLogPath = hybridLogPath;
		this.maxRecords = maxRecords;
	}

	async start(intervalMs: number = 2000): Promise<void> {
		console.log('Log Monitor started. Press Ctrl+C to exit.');
		console.log(`Monitoring logs with refresh interval of ${intervalMs}ms\n`);

		// Initial fetch
		await this.fetchAllLogs();
		this.displaySummary();

		// Set up interval
		const interval = setInterval(async () => {
			await this.fetchAllLogs();
			console.clear();
			this.displaySummary();
		}, intervalMs);

		// Handle exit
		process.on('SIGINT', () => {
			clearInterval(interval);
			console.log('\nLog Monitor stopped.');
			process.exit(0);
		});
	}

	private async fetchAllLogs(): Promise<void> {
		await Promise.all([
			this.fetchLogs(this.logPath, (data) => {
				this.logs = this.parseLogData(data as unknown as LogData[]);
			}),
			this.fetchLogs(this.specificationLogPath, (data) => {
				this.specificationLogs = this.parseLogData(data as unknown as LogRecord[]);
			}),
			this.fetchLogs(this.signatureLogPath, (data) => {
				this.signatureLogs = this.parseLogData(data as unknown as LogRecord[]);
			}),
			this.fetchLogs(this.hybridLogPath, (data) => {
				this.hybridLogs = this.parseLogData(data as unknown as LogRecord[]);
			}),
		]);
	}

	private async fetchLogs<T>(filePath: string, callback: (data: T[]) => void): Promise<void> {
		try {
			const csvText = fs.readFileSync(path.resolve(filePath), 'utf-8');
			const { data } = Papa.parse(csvText, { header: true, skipEmptyLines: true });
			callback(data as T[]);
		} catch (err) {
			console.error(`Error reading ${filePath}:`, err);
		}
	}

	private parseLogData<T>(data: T[]): T[] {
		return data.map((item: any, index: number) => ({ ...item, index })).filter((_, index) => index < this.maxRecords);
	}

	private calculateConfusionMatrix(logEntries: LogRecord[], mainLogs: LogData[]): ConfusionMatrix {
		const matrix: ConfusionMatrix = {
			truePositive: 0,
			falsePositive: 0,
			trueNegative: 0,
			falseNegative: 0,
		};

		// Process each log entry where we have both detection results and ground truth
		for (let i = 0; i < Math.min(logEntries.length, mainLogs.length); i++) {
			const isActualAttack = mainLogs[i]['attack.type'] !== '';
			const isDetected = logEntries[i].detected === 'true';

			if (isActualAttack && isDetected) {
				matrix.truePositive++;
			} else if (!isActualAttack && isDetected) {
				matrix.falsePositive++;
			} else if (isActualAttack && !isDetected) {
				matrix.falseNegative++;
			} else if (!isActualAttack && !isDetected) {
				matrix.trueNegative++;
			}
		}

		return matrix;
	}

	private displayConfusionMatrix(title: string, matrix: ConfusionMatrix): void {
		const total = matrix.truePositive + matrix.falsePositive + matrix.trueNegative + matrix.falseNegative;
		const tpPercent = total > 0 ? ((matrix.truePositive / total) * 100).toFixed(1) : '0.0';
		const fpPercent = total > 0 ? ((matrix.falsePositive / total) * 100).toFixed(1) : '0.0';
		const fnPercent = total > 0 ? ((matrix.falseNegative / total) * 100).toFixed(1) : '0.0';
		const tnPercent = total > 0 ? ((matrix.trueNegative / total) * 100).toFixed(1) : '0.0';

		console.log(`\n${title} CONFUSION MATRIX:`);

		// Create the table
		console.log('┌─────────┬───────────────────────────────────────┐');
		console.log('│         │ Prediction                            │');
		console.log('│         ├───────────────────┬───────────────────┤');
		console.log('│         │ Normal            │ Anomaly           │');
		console.log('├─────────┼───────────────────┼───────────────────┤');
		console.log(
			`│ Actual  │ ${matrix.trueNegative.toString().padEnd(17)} │ ${matrix.falsePositive.toString().padEnd(17)} │`
		);
		console.log('│ Normal  │                   │                   │');
		console.log('├─────────┼───────────────────┼───────────────────┤');
		console.log(
			`│ Actual  │ ${matrix.falseNegative.toString().padEnd(17)} │ ${matrix.truePositive.toString().padEnd(17)} │`
		);
		console.log('│ Anomaly │                   │                   │');
		console.log('└─────────┴───────────────────┴───────────────────┘');
	}

	private displaySummary(): void {
		const attackCount = this.logs.filter((log) => log['attack.type'] !== '').length;
		const specAnomalyCount = this.specificationLogs.filter((log) => log.detected !== 'false').length;
		const sigDetectedCount = this.signatureLogs.filter((log) => log.detected !== 'false').length;
		const hybridDetectedCount = this.hybridLogs.filter((log) => log.detected !== 'false').length;
		const missedAttacks = this.logs.filter(
			(log, index) =>
				log['attack.type'] !== '' && index < this.hybridLogs.length && this.hybridLogs[index]?.detected === 'false'
		).length;

		console.log('===== SECURITY MONITORING SYSTEM =====');
		console.log('SUMMARY:');
		console.log(`Total Attacks Logged: ${attackCount}`);
		console.log(`Specification Anomalies: ${specAnomalyCount}`);
		console.log(`Signature Detections: ${sigDetectedCount}`);
		console.log(`Hybrid Detections: ${hybridDetectedCount}`);
		console.log(`Missed Attacks: ${missedAttacks}`);
		console.log('=====================================\n');

		// Display recent attacks
		console.log('RECENT ATTACKS:');
		this.displayTable(this.logs.filter((log) => log['attack.type'] !== '').slice(0, 10), [
			'index',
			'attack.type',
			'request.method',
			'request.url',
		]);
		console.log('\n');

		// Display recent detections by detection type
		console.log('RECENT HYBRID DETECTIONS:');
		this.displayDetectionTable(this.hybridLogs.filter((log) => log.detected !== 'false').slice(0, 5));
		console.log('\n');

		console.log('RECENT SPECIFICATION ANOMALIES:');
		this.displayDetectionTable(this.specificationLogs.filter((log) => log.detected !== 'false').slice(0, 5));
		console.log('\n');

		console.log('RECENT SIGNATURE DETECTIONS:');
		this.displayDetectionTable(this.signatureLogs.filter((log) => log.detected !== 'false').slice(0, 5));

		// Calculate and display confusion matrices
		console.log('\n===== DETECTION PERFORMANCE =====');

		const signatureMatrix = this.calculateConfusionMatrix(this.signatureLogs, this.logs);
		this.displayConfusionMatrix('SIGNATURE-BASED DETECTION', signatureMatrix);

		const specificationMatrix = this.calculateConfusionMatrix(this.specificationLogs, this.logs);
		this.displayConfusionMatrix('SPECIFICATION-BASED DETECTION', specificationMatrix);

		const hybridMatrix = this.calculateConfusionMatrix(this.hybridLogs, this.logs);
		this.displayConfusionMatrix('HYBRID DETECTION', hybridMatrix);

		// Calculate and display performance metrics
		console.log('\nPERFORMANCE METRICS:');
		this.displayPerformanceMetrics('Signature-Based', signatureMatrix);
		this.displayPerformanceMetrics('Specification-Based', specificationMatrix);
		this.displayPerformanceMetrics('Hybrid', hybridMatrix);
	}

	private displayPerformanceMetrics(detectionType: string, matrix: ConfusionMatrix): void {
		const accuracy =
			(matrix.truePositive + matrix.trueNegative) /
			(matrix.truePositive + matrix.trueNegative + matrix.falsePositive + matrix.falseNegative);

		const precision = matrix.truePositive / (matrix.truePositive + matrix.falsePositive) || 0;

		const recall = matrix.truePositive / (matrix.truePositive + matrix.falseNegative) || 0;

		const f1Score = 2 * ((precision * recall) / (precision + recall)) || 0;

		console.log(
			`${detectionType}: Accuracy: ${(accuracy * 100).toFixed(2)}%, Precision: ${(precision * 100).toFixed(
				2
			)}%, Recall: ${(recall * 100).toFixed(2)}%, F1-Score: ${(f1Score * 100).toFixed(2)}%`
		);
	}

	private displayTable(data: any[], columns: string[]): void {
		if (data.length === 0) {
			console.log('No data to display');
			return;
		}

		// Print header
		console.log(columns.map((col) => col.padEnd(15)).join(' | '));
		console.log(columns.map(() => '---------------').join('-+-'));

		// Print rows
		data.forEach((row) => {
			const rowData = columns.map((col) => {
				const value = String(row[col] || '').substring(0, 14);
				return value.padEnd(15);
			});
			console.log(rowData.join(' | '));
		});
	}

	private displayDetectionTable(data: LogRecord[]): void {
		if (data.length === 0) {
			console.log('No detections to display');
			return;
		}

		// Print header
		console.log('Index'.padEnd(10) + ' | ' + 'Attack Type'.padEnd(20) + ' | ' + 'Reason'.padEnd(40));
		console.log('----------+----------------------+------------------------------------------');

		// Print rows
		data.forEach((row) => {
			let attackType = '';
			try {
				const requestObj = JSON.parse(row.request);
				attackType = requestObj['attack-type'] || '';
			} catch (e) {
				attackType = 'Unknown';
			}

			console.log(
				String(row.index || '').padEnd(10) +
					' | ' +
					attackType.substring(0, 19).padEnd(20) +
					' | ' +
					row.reason.substring(0, 39).padEnd(40)
			);
		});
	}
}

// Usage
const monitor = new LogMonitor(
	filePath('/public/ca_formatted_logs.csv'),
	filePath('/public/signature_detection_logs.csv'),
	filePath('/public/specification_detection_logs.csv'),
	filePath('/public/hybrid_detection_logs.csv'),
	10000
);
monitor.start(360000);

// Example to run with custom paths and interval
// const monitor = new LogMonitor(
//   './data/logs.csv',
//   './data/spec_logs.csv',
//   './data/sig_logs.csv',
//   './data/hybrid_logs.csv',
//   5000 // Max records
// );
// monitor.start(5000); // Refresh every 5 seconds
