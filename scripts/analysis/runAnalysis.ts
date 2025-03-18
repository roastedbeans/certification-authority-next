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
	attackType?: string;
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

interface PerformanceMetrics {
	accuracy: number;
	precision: number;
	recall: number;
	f1Score: number;
}

export interface DetectionSummary {
	attackCount: number;
	specAnomalyCount: number;
	sigDetectedCount: number;
	hybridDetectedCount: number;
	missedAttacks: number;
	recentAttacks: Partial<LogData>[];
	recentHybridDetections: Partial<LogRecord>[];
	recentSpecificationAnomalies: Partial<LogRecord>[];
	recentSignatureDetections: Partial<LogRecord>[];
	signatureMatrix: ConfusionMatrix;
	specificationMatrix: ConfusionMatrix;
	hybridMatrix: ConfusionMatrix;
	signatureMetrics: PerformanceMetrics;
	specificationMetrics: PerformanceMetrics;
	hybridMetrics: PerformanceMetrics;
}

class LogAnalyzer {
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

	async analyze(): Promise<DetectionSummary> {
		await this.fetchAllLogs();
		return this.generateSummary();
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
			throw new Error(`Error reading ${filePath}: ${err}`);
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

	private calculatePerformanceMetrics(matrix: ConfusionMatrix): PerformanceMetrics {
		const accuracy =
			(matrix.truePositive + matrix.trueNegative) /
			(matrix.truePositive + matrix.trueNegative + matrix.falsePositive + matrix.falseNegative);

		const precision = matrix.truePositive / (matrix.truePositive + matrix.falsePositive) || 0;

		const recall = matrix.truePositive / (matrix.truePositive + matrix.falseNegative) || 0;

		const f1Score = 2 * ((precision * recall) / (precision + recall)) || 0;

		return {
			accuracy,
			precision,
			recall,
			f1Score,
		};
	}

	private extractDetectionData(record: LogRecord): Partial<LogRecord> {
		let attackType = '';
		try {
			const requestObj = JSON.parse(record.request);
			attackType = requestObj['attack-type'] || '';
		} catch (e) {
			attackType = 'Unknown';
		}

		return {
			index: record.index,
			detectionType: record.detectionType,
			reason: record.reason,
			attackType: attackType,
		};
	}

	private generateSummary(): DetectionSummary {
		const attackCount = this.logs.filter((log) => log['attack.type'] !== '').length;
		const specAnomalyCount = this.specificationLogs.filter((log) => log.detected !== 'false').length;
		const sigDetectedCount = this.signatureLogs.filter((log) => log.detected !== 'false').length;
		const hybridDetectedCount = this.hybridLogs.filter((log) => log.detected !== 'false').length;
		const missedAttacks = this.logs.filter(
			(log, index) =>
				log['attack.type'] !== '' && index < this.hybridLogs.length && this.hybridLogs[index]?.detected === 'false'
		).length;

		// Recent attacks
		const recentAttacks = this.logs
			.filter((log) => log['attack.type'] !== '')
			.slice(0, 10)
			.map((log) => ({
				index: log.index,
				'attack.type': log['attack.type'],
				'request.method': log['request.method'],
				'request.url': log['request.url'],
			}));

		// Recent detections
		const recentHybridDetections = this.hybridLogs
			.filter((log) => log.detected !== 'false')
			.slice(0, 5)
			.map((log) => this.extractDetectionData(log));

		const recentSpecificationAnomalies = this.specificationLogs
			.filter((log) => log.detected !== 'false')
			.slice(0, 5)
			.map((log) => this.extractDetectionData(log));

		const recentSignatureDetections = this.signatureLogs
			.filter((log) => log.detected !== 'false')
			.slice(0, 5)
			.map((log) => this.extractDetectionData(log));

		// Calculate confusion matrices
		const signatureMatrix = this.calculateConfusionMatrix(this.signatureLogs, this.logs);
		const specificationMatrix = this.calculateConfusionMatrix(this.specificationLogs, this.logs);
		const hybridMatrix = this.calculateConfusionMatrix(this.hybridLogs, this.logs);

		// Calculate performance metrics
		const signatureMetrics = this.calculatePerformanceMetrics(signatureMatrix);
		const specificationMetrics = this.calculatePerformanceMetrics(specificationMatrix);
		const hybridMetrics = this.calculatePerformanceMetrics(hybridMatrix);

		return {
			attackCount,
			specAnomalyCount,
			sigDetectedCount,
			hybridDetectedCount,
			missedAttacks,
			recentAttacks,
			recentHybridDetections,
			recentSpecificationAnomalies,
			recentSignatureDetections,
			signatureMatrix,
			specificationMatrix,
			hybridMatrix,
			signatureMetrics,
			specificationMetrics,
			hybridMetrics,
		};
	}
}

// Export the class and a convenient function to run the analysis
export default LogAnalyzer;

// One-time analysis function
export async function analyzeSecurityLogs(
	mainLogPath: string = filePath('/public/ca_formatted_logs.csv'),
	signatureLogPath: string = filePath('/public/signature_detection_logs.csv'),
	specificationLogPath: string = filePath('/public/specification_detection_logs.csv'),
	hybridLogPath: string = filePath('/public/hybrid_detection_logs.csv'),
	maxRecords: number = 10000
): Promise<DetectionSummary> {
	try {
		const analyzer = new LogAnalyzer(mainLogPath, specificationLogPath, signatureLogPath, hybridLogPath, maxRecords);
		return await analyzer.analyze();
	} catch (error) {
		console.error('Error analyzing security logs:', error);
		throw error;
	}
}

// Example usage:
/*
import { analyzeSecurityLogs } from './LogAnalyzer';

async function runAnalysis() {
  const summary = await analyzeSecurityLogs();
  return summary;
}

runAnalysis().then(summary => {
  // Use the summary object as needed
  console.log(JSON.stringify(summary, null, 2));
});
*/
