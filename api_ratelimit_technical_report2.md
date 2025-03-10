# TECHNICAL REPORT: SLIDING WINDOW RATE LIMITING FOR CERTIFICATION AUTHORITY API

## IMPLEMENTATION OVERVIEW

The certification authority API implements a focused rate limiting solution based on the sliding window algorithm. This approach provides precise control over request rates while avoiding the traffic spikes associated with fixed window implementations. The system is designed to analyze request logs and identify rate limit violations according to configurable thresholds based on client identifiers and API endpoints.

## SLIDING WINDOW ALGORITHM

### Core Implementation

The sliding window rate limiting algorithm tracks requests within a rolling time window (typically 1 minute), providing a smoother and more accurate rate limiting experience compared to fixed window approaches.

```typescript
private checkSlidingWindowLimit(key: string, limit: number, timestamp: number): RateLimitResult {
  // Window size: 1 minute (60,000 ms)
  const windowSize = 60000;
  const windowStart = timestamp - windowSize;

  // Initialize or get timestamps for this key
  if (!this.requestStore.has(key)) {
    this.requestStore.set(key, []);
  }

  // Get timestamps and filter out those outside the current window
  const timestamps = this.requestStore.get(key)!;
  const validTimestamps = timestamps.filter(time => time > windowStart);
  
  // Update the store with only valid timestamps
  this.requestStore.set(key, validTimestamps);

  // Check if limit is exceeded
  if (validTimestamps.length >= limit) {
    return {
      exceeded: true,
      reason: `Rate limit of ${limit} requests per minute exceeded for ${key}`,
      remaining: 0,
      resetAt: validTimestamps.length > 0 ? validTimestamps[0] + windowSize : timestamp + windowSize
    };
  }

  // Add current timestamp to the window
  validTimestamps.push(timestamp);
  this.requestStore.set(key, validTimestamps);

  // Return successful result with remaining count
  return {
    exceeded: false,
    reason: '',
    remaining: limit - validTimestamps.length,
    resetAt: timestamp + windowSize
  };
}
```

### Key Advantages of Sliding Window

1. **Smooth Rate Limiting**: Prevents the "edge effect" traffic spikes that occur at window boundaries in fixed window implementations.

2. **Accurate Time Window**: Each request is evaluated against a precise time window relative to its own timestamp.

3. **Fair Resource Distribution**: Ensures equitable API access by preventing bursts of requests at window transitions.

4. **Memory Efficient**: Only stores timestamps that fall within the active time window, automatically discarding older entries.

## LOG ANALYSIS IMPLEMENTATION

The system reads request logs from the `requests_responses.txt` file, parses each log entry, and applies the sliding window rate limiting algorithm to detect violations. This approach allows for retroactive analysis of API traffic patterns and identification of potential abuse.

### Log Parsing

```typescript
export function parseLogLine(line: string): LogEntry | null {
  try {
    // Format from requests_responses.txt is:
    // ||[timestamp] [request {...}] [response {...}]
    const parts = line.split('[');
    
    if (parts.length < 4) return null;
    
    const requestPart = '[' + parts[2];
    const responsePart = '[' + parts[3];
    
    // Extract and parse the request and response JSON
    const requestMatch = requestPart.match(/\[request (.*?)\]/);
    const responseMatch = responsePart.match(/\[response (.*?)\]/);
    
    if (!requestMatch || !responseMatch) return null;
    
    const request = JSON.parse(requestMatch[1]);
    const response = JSON.parse(responseMatch[1]);
    
    return { request, response };
  } catch (e) {
    console.error('Error parsing log line:', e);
    return null;
  }
}

export function parseTimestamp(line: string): Date | null {
  try {
    const timestampMatch = line.match(/\|\|\[(.*?)\]/);
    if (!timestampMatch) return null;
    
    return new Date(timestampMatch[1]);
  } catch (e) {
    console.error('Error parsing timestamp:', e);
    return null;
  }
}
```

### Rate Limit Analysis

```typescript
export async function analyzeLogsWithRateLimit(logFilePath: string): Promise<void> {
  // Read the entire log file
  const logContent = fs.readFileSync(logFilePath, 'utf8');
  const logLines = logContent.split('\n').filter(line => line.trim() !== '');
  
  // Create rate limiter instance
  const rateLimiter = new SlidingWindowRateLimiter();
  
  // Process each log line
  for (const line of logLines) {
    const entry = parseLogLine(line);
    if (!entry) continue;
    
    // Extract timestamp for more accurate rate limiting
    const timestamp = parseTimestamp(line);
    if (timestamp) {
      // Override the timestamp extraction method for accurate historical analysis
      rateLimiter.extractTimestamp = () => timestamp.getTime();
    }
    
    // Check rate limit
    const result = rateLimiter.checkRateLimit(entry);
    
    // Log rate limit violations
    if (result.exceeded) {
      await logRateLimitViolation(entry, result, timestamp);
      console.log(`[RATE LIMIT VIOLATION] ${result.reason}`);
    }
  }
}
```

## MULTI-DIMENSIONAL RATE LIMITING

The implementation applies rate limits across multiple dimensions to provide comprehensive protection:

### Client-Based Rate Limiting

Identifies clients using the first 10 characters of the `x-api-tran-id` header, allowing for client-specific rate limits:

```typescript
private extractClientId(entry: LogEntry): string {
  // Use the first 10 characters of x-api-tran-id as client ID
  const transactionId = entry.request['x-api-tran-id'] || '';
  return transactionId.substring(0, 10);
}
```

This enables different rate limits for different clients:

```typescript
clientRateLimits: {
  'anya123456': {
    requestsPerMinute: 30, // Stricter limit for specific client
  }
}
```

### Endpoint-Based Rate Limiting

Extracts the endpoint from the request URL to apply endpoint-specific rate limits:

```typescript
private extractEndpoint(entry: LogEntry): string {
  try {
    const url = new URL(entry.request.url);
    return url.pathname;
  } catch (e) {
    // If URL parsing fails, extract path part from the URL string
    const urlPath = entry.request.url.split('?')[0];
    return urlPath;
  }
}
```

This enables different rate limits for different endpoints:

```typescript
endpointRateLimits: {
  '/api/v2/mgmts/oauth/2.0/token': {
    requestsPerMinute: 5, // Stricter limit for authentication endpoint
  },
  '/api/oauth/2.0/token': {
    requestsPerMinute: 5, // Stricter limit for authentication endpoint
  },
  '/api/ca/sign_request': {
    requestsPerMinute: 10, 
  }
}
```

## DETECTION OUTPUT FORMAT

Rate limit violations are recorded in the same format as the specification-based detection system, ensuring consistency across security mechanisms:

```typescript
async function logRateLimitViolation(
  entry: LogEntry, 
  result: RateLimitResult,
  timestamp: Date | null
): Promise<void> {
  const logTimestamp = timestamp ? timestamp.toISOString() : new Date().toISOString();
  
  const record = {
    timestamp: logTimestamp,
    detectionType: 'RateLimit',
    detected: result.exceeded,
    reason: result.reason,
    request: JSON.stringify(entry.request),
    response: JSON.stringify(entry.response)
  };

  const csvLine = `${record.timestamp},${record.detectionType},${record.detected},${record.reason.replace(
    /,/g,
    ';'
  )},${record.request.replace(/,/g, ';')},${record.response.replace(/,/g, ';')}\n`;

  fs.appendFileSync(DETECTION_LOG_PATH, csvLine);
}
```

The output CSV file contains the following columns:
- timestamp: When the violation was detected
- detectionType: Always "RateLimit" for rate limit violations
- detected: Boolean indicating if the limit was exceeded
- reason: Detailed explanation of which limit was exceeded and why
- request: JSON representation of the request that triggered the violation
- response: JSON representation of the response associated with the request

## USE CASES

### 1. Authentication Endpoint Protection

The system applies strict rate limits to authentication endpoints to prevent brute force attacks:

```typescript
endpointRateLimits: {
  '/api/v2/mgmts/oauth/2.0/token': {
    requestsPerMinute: 5,
  },
  '/api/oauth/2.0/token': {
    requestsPerMinute: 5,
  }
}
```

This significantly limits an attacker's ability to guess credentials or attempt token theft.

### 2. Client-Specific Rate Limiting

Different clients may have different legitimate usage patterns, which the system accommodates through client-specific limits:

```typescript
clientRateLimits: {
  'anya123456': {
    requestsPerMinute: 30,
  }
}
```

This allows for tailored rate limits based on expected client behavior, preventing false positives while maintaining security.

### 3. Retroactive Analysis

By processing historical logs, the system can identify past rate limit violations that might indicate security incidents:

```typescript
const timestamp = parseTimestamp(line);
if (timestamp) {
  rateLimiter.extractTimestamp = () => timestamp.getTime();
}
```

This enables security teams to investigate patterns of abuse over time and adjust rate limits accordingly.

## PERFORMANCE CONSIDERATIONS

### Memory Usage

The sliding window algorithm stores request timestamps in memory, which has implications for high-traffic environments:

- Each timestamp consumes 8 bytes (64-bit number)
- For a client making 30 requests per minute: 240 bytes per client
- With 10,000 active clients: approximately 2.4 MB of memory

The implementation minimizes memory usage by:
1. Automatically purging timestamps outside the time window
2. Using efficient data structures (Map and arrays)
3. Storing only the minimum required information (timestamps)

### Computational Complexity

The sliding window algorithm has a time complexity of O(n) where n is the number of requests in the window:

- Request evaluation: O(n) for filtering timestamps outside the window
- Window maintenance: O(1) for adding new timestamps
- Rate limit checking: O(1) for comparing count against limit

For typical use cases with moderate request rates, this performance impact is negligible.

## CONCLUSION

The sliding window rate limiting implementation provides a precise, fair, and memory-efficient solution for protecting the Certification Authority API from abuse. By analyzing request logs with a focus on client identifiers and endpoint patterns, it can detect and prevent various forms of API abuse while maintaining accurate time-based rate limiting.

The integration with the existing detection system ensures consistent logging and analysis of security events, while the configurable nature of the rate limits allows for adaptation to different environments and security requirements. This focused approach enables better protection for sensitive endpoints like authentication services while allowing reasonable access for legitimate API usage. 