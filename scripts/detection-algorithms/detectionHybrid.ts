import { filePath, LogEntry, FilePosition, initializeCSV, readNewCSVLogEntries, logDetectionResult } from '../utils';
import { SpecificationBasedDetection } from './detectionSpecification';
import { SignatureBasedDetection } from './detectionSignature';

// Track timing statistics
let totalProcessingTime = 0;
let totalRequestsProcessed = 0;

// Main Detection Function
async function detectIntrusions(entry: LogEntry): Promise<void> {
	const requestStartTime = performance.now();

	const specificationDetector = new SpecificationBasedDetection();

	// Start timing for specification-based detection
	const specificationStartTime = performance.now();
	const specificationResult = specificationDetector.detect(entry);
	const specificationEndTime = performance.now();
	const specificationDuration = specificationEndTime - specificationStartTime;

	if (specificationResult.detected) {
		console.log('########## Primary (Specification-based) Security Complete! ##########');
		console.log(`########## Specification Detection Time: ${specificationDuration.toFixed(10)}ms ##########`);
		await logDetectionResult(entry, 'hybrid', specificationResult);
		console.log('########## ⚠️ Intrusion Detected! ##########');
		console.log('Specification-based:', specificationResult);
	} else {
		// await logDetectionResult(entry, 'Specification', specificationResult);
		console.log('########## Primary (Specification-based) Security Complete! ##########');
		console.log(`########## Specification Detection Time: ${specificationDuration.toFixed(10)}ms ##########`);
		console.log('########## Initializing Secondary (Signature-based) Detection! ##########');
		console.log('########## Matching attack patterns... ##########');

		const signatureDetector = new SignatureBasedDetection();

		// Start timing for signature-based detection
		const signatureStartTime = performance.now();
		const signatureResult = signatureDetector.detect(entry);
		const signatureEndTime = performance.now();
		const signatureDuration = signatureEndTime - signatureStartTime;

		if (signatureResult.detected) {
			await logDetectionResult(entry, 'hybrid', signatureResult);
			console.log('########## ⚠️ Intrusion Detected! ##########');
			console.log('Signature-based:', signatureResult);
			console.log(`########## Signature Detection Time: ${signatureDuration.toFixed(10)}ms ##########`);
			console.log('########## Secondary (Signature-based) Security Complete! ##########');
		} else {
			await logDetectionResult(entry, 'hybrid', signatureResult);
			console.log(`########## Signature Detection Time: ${signatureDuration.toFixed(10)}ms ##########`);
			console.log('########## Secondary (Signature-based) Security Complete! ##########');
		}
	}

	const requestEndTime = performance.now();
	const requestDuration = requestEndTime - requestStartTime;

	// Update timing statistics
	totalProcessingTime += requestDuration;
	totalRequestsProcessed++;

	const currentAverage = totalProcessingTime / totalRequestsProcessed;
	console.log(`########## Total Request Processing Time: ${requestDuration.toFixed(10)}ms ##########`);
	console.log(`########## Average Time Per Request: ${currentAverage.toFixed(10)}ms ##########`);
}

// Main Function to Start Detection
export async function startHybridDetection(logFilePath: string) {
	try {
		await initializeCSV(filePath('/public/hybrid_detection_logs.csv'), 'detection');

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
					try {
						await detectIntrusions(entry);
					} catch (error) {
						console.error('Error during intrusion detection:', error);
						// Continue processing other entries
					}
				}
			}
		} else {
			console.log('No existing entries found in the log file.');
		}

		return 'done';
	} catch (error) {
		console.error('Error starting detection:', error);
		// Don't just return 'error', return the actual error message for better debugging
		return String(error);
	}
}
