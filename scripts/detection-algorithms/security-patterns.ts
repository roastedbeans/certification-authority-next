// Regular expression patterns for detecting known attack signatures
export const securityPatterns = {
	sqlInjection: [
		/('|"|`)\s*(OR|AND)\s*[0-9]+\s*=\s*[0-9]+/i,
		/('|"|`)\s*(OR|AND)\s*('|"|`)[^'"]*('|"|`)\s*=\s*('|"|`)/i,
		/('|"|`)\s*(OR|AND)\s*[0-9]+\s*=\s*[0-9]+\s*(--|#|\/\*)/i,
		/;\s*DROP\s+TABLE/i,
		/UNION\s+(ALL\s+)?SELECT/i,
		/SELECT\s+.*\s+FROM\s+information_schema/i,
		/ALTER\s+TABLE/i,
		/INSERT\s+INTO/i,
		/DELETE\s+FROM/i,
		/WAITFOR\s+DELAY/i,
		/SLEEP\s*\(/i,
		/BENCHMARK\s*\(/i,
		/EXEC\s*(xp_|sp_)/i,
	],
	xss: [
		/<script.*?>.*?<\/script>/i,
		/javascript:/i,
		/onerror\s*=/i,
		/onload\s*=/i,
		/onclick\s*=/i,
		/onmouseover\s*=/i,
		/onfocus\s*=/i,
		/onblur\s*=/i,
		/onkeydown\s*=/i,
		/onkeypress\s*=/i,
		/onkeyup\s*=/i,
		/ondblclick\s*=/i,
		/onchange\s*=/i,
		/alert\s*\(/i,
		/eval\s*\(/i,
		/document\.cookie/i,
		/document\.location/i,
		/document\.write/i,
		/document\.referrer/i,
		/window\.location/i,
		/window\.open/i,
		/<img.*?src=.*?onerror=.*?>/i,
	],
	xxe: [/<!DOCTYPE.*?SYSTEM/i, /<!ENTITY.*?SYSTEM/i, /<!\[CDATA\[.*?\]\]>/i],
	commandInjection: [/\s*\|\s*(\w+)/i, /`.*?`/, /\$\(.*?\)/, /&&[\s\w\/]+/i, /\|\|[\s\w\/]+/i],
	directoryTraversal: [
		/\.\.\//,
		/\.\.\\/,
		/%2e%2e\//i,
		/%2e%2e\\/i,
		/\.\.%2f/i,
		/\.\.%5c/i,
		/%252e%252e\//i,
		/%252e%252e\\/i,
	],
	fileUpload: [
		/\.php$/i,
		/\.asp$/i,
		/\.aspx$/i,
		/\.exe$/i,
		/\.jsp$/i,
		/\.jspx$/i,
		/\.sh$/i,
		/\.bash$/i,
		/\.csh$/i,
		/\.bat$/i,
		/\.cmd$/i,
		/\.dll$/i,
		/\.jar$/i,
		/\.war$/i,
	],
	cookieInjection: [/document\.cookie.*?=/i],
	maliciousHeaders: [/X-Forwarded-Host:\s*[^.]+\.[^.]+\.[^.]+/i],
	ssrf: [
		/127\.0\.0\.1/i,
		/0\.0\.0\.0/i,
		/::1/i,
		/192\.168\./i,
		/172\.(1[6-9]|2[0-9]|3[0-1])\./i,
		/169\.254\./i,
		/x00/i,
	],
};
