import fs from 'fs';
import readline from 'readline';

const logFilePath = 'logs/server.log'; // Path to log file

const analyzeLog = (logLine: string) => {
	if (logLine.includes('Request:')) {
		console.log('[INFO] Request:', logLine);
	}
	if (logLine.includes('Response:')) {
		console.log('[INFO] Response:', logLine);
	}

	if (logLine.match(/('|--|;|select|union|drop|insert|update|delete)/i)) {
		console.log('⚠️ [WARNING] Possible SQL Injection Detected!', logLine);
	}
};

const stream = fs.createReadStream(logFilePath, { encoding: 'utf8', flags: 'a+' });
const rl = readline.createInterface({ input: stream });

rl.on('line', (line) => {
	analyzeLog(line);
});

console.log('[LOG WATCHER] Monitoring logs...');
