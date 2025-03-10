# Advanced Rate Limiting for Certification Authority API

This document provides information about the enhanced rate limiting system implemented for the Certification Authority API to protect against various types of attacks and ensure system stability.

## Overview

The rate limiting feature is designed to protect the API from abuse, prevent denial-of-service attacks, and ensure fair resource distribution among clients. It provides a flexible, configurable approach to rate limiting that can be adapted to different environments and requirements.

## Key Features

### Multiple Rate Limiting Strategies

- **Fixed Window**: Counts requests within specific time windows (e.g., per minute)
- **Sliding Window**: Maintains a rolling window of requests for smoother rate limiting
- **Token Bucket** (planned): Allows for burst traffic while maintaining average rate limits

### Multi-dimensional Rate Limiting

- **Client-based limits**: Different limits for different clients/API keys
- **Endpoint-specific limits**: Configure stricter limits for sensitive endpoints
- **Method-specific limits**: Different limits for different HTTP methods (GET, POST, etc.)
- **IP-based fallback**: Apply limits based on IP when client ID is not available

### Payload Size Limiting

- Protect against large payload attacks that could consume excessive resources
- Configure size limits globally, per endpoint, or per specific field
- Detailed reporting of which fields exceeded size limits

### Distributed Rate Limiting

- Redis-based implementation for multi-server deployments
- Consistent rate limiting across all API instances
- Automatic cleanup of expired rate limit data

### Observability

- Standard rate limit headers (RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset)
- Detailed logging of rate limit violations for analysis
- Support for alerting on suspicious patterns

### Configurable Actions

- Block requests that exceed limits
- Delay requests that exceed limits (planned)
- Log-only mode for monitoring without enforcement

## Implementation Details

The rate limiting system is implemented in the `rateLimit.ts` file and consists of:

1. **RateLimitConfig Interface**: Defines the configuration options for the rate limiter
2. **RateLimiter Class**: Core implementation of rate limiting strategies
3. **Helper Functions**: For logging and applying rate limits

### Configuration Options

```typescript
interface RateLimitConfig {
	enabled: boolean;
	strategy: 'fixed-window' | 'sliding-window' | 'token-bucket';

	globalRateLimit: {
		requestsPerMinute: number;
		burstAllowance: number;
	};

	clientRateLimits: {
		[clientId: string]: {
			requestsPerMinute: number;
			maxPayloadSize: number;
		};
	};

	endpointRateLimits: {
		[endpoint: string]: {
			requestsPerMinute: number;
			maxPayloadSize: number;
		};
	};

	// ... and more configuration options
}
```

## Security Benefits

### Protection Against Common Attacks

1. **Denial of Service (DoS) Attacks**

   - Rate limiting prevents attackers from overwhelming the API with excessive requests
   - Payload size limits prevent resource exhaustion from large requests

2. **Brute Force Attacks**

   - Limits on authentication endpoints prevent credential stuffing and password guessing

3. **Scraping and Data Harvesting**

   - Rate limits make bulk data collection inefficient and detectable

4. **API Abuse**
   - Prevents misuse of API resources by legitimate clients
   - Ensures fair distribution of resources across all clients

### Integration with Other Security Measures

The rate limiting system works in conjunction with:

- API key authentication
- Request specification validation
- Anomaly detection
- Security logging and monitoring

## Use Cases

### 1. Protecting Authentication Endpoints

Authentication endpoints are particularly sensitive and require stricter rate limits:

```typescript
endpointRateLimits: {
  '/api/v2/mgmts/oauth/2.0/token': {
    requestsPerMinute: 20,
    maxPayloadSize: 1500
  }
}
```

### 2. Different Limits for Different Clients

Some clients may need higher limits based on legitimate business needs:

```typescript
clientRateLimits: {
  'trusted-partner-1': {
    requestsPerMinute: 300,
    maxPayloadSize: 5000
  },
  'standard-client': {
    requestsPerMinute: 100,
    maxPayloadSize: 2000
  }
}
```

### 3. Environment-Specific Configurations

Development environments may have different needs than production:

```typescript
// Development config
{
  enabled: true,
  strategy: 'sliding-window',
  globalRateLimit: {
    requestsPerMinute: 1000,
    burstAllowance: 100
  },
  redisConfig: {
    enabled: false
  },
  limitExceededAction: 'log-only'
}

// Production config
{
  enabled: true,
  strategy: 'sliding-window',
  globalRateLimit: {
    requestsPerMinute: 500,
    burstAllowance: 50
  },
  redisConfig: {
    enabled: true
  },
  limitExceededAction: 'block'
}
```

## Integration

### Basic Usage

```typescript
import { RateLimiter } from './rateLimit';
import { LogEntry } from './types';

// Create a rate limiter with default config
const limiter = new RateLimiter();

// Check if a request exceeds limits
async function handleRequest(entry: LogEntry) {
	const result = await limiter.checkRateLimits(entry);

	if (result.exceeded) {
		console.log(`Rate limit exceeded: ${result.reason}`);
		return {
			statusCode: 429,
			headers: limiter.getRateLimitHeaders(result),
			body: { error: 'Too Many Requests', message: result.reason },
		};
	}

	// Process the request normally
	// ...
}
```

### Middleware Integration

In an Express.js-like environment:

```typescript
function rateLimitMiddleware(req, res, next) {
	const entry = convertRequestToLogEntry(req);
	const limiter = new RateLimiter();

	limiter
		.checkRateLimits(entry)
		.then((result) => {
			// Add rate limit headers to all responses
			const headers = limiter.getRateLimitHeaders(result);
			Object.entries(headers).forEach(([key, value]) => {
				res.setHeader(key, value);
			});

			if (result.exceeded) {
				return res.status(429).json({
					error: 'Too Many Requests',
					message: result.reason,
				});
			}

			next();
		})
		.catch((err) => {
			next(err);
		});
}
```

## Improvement Plans

1. **Additional Strategies**:

   - Add token bucket algorithm for better burst handling
   - Implement adaptive rate limiting based on system load

2. **Enhanced Monitoring**:

   - Dashboard for visualizing rate limit usage
   - Predictive alerts when clients approach limits

3. **Client Notifications**:

   - Webhook notifications when clients repeatedly hit limits
   - API for clients to check their current rate limit status

4. **Machine Learning Integration**:
   - Use ML to detect abusive patterns that stay under rate limits
   - Dynamically adjust limits based on client behavior

## Performance Considerations

1. **Memory Usage**: In-memory rate limiting stores request timestamps for each client/endpoint
2. **Redis Performance**: Redis-based rate limiting adds network overhead but scales better
3. **Computational Cost**: The sliding window algorithm is more CPU-intensive than fixed window

## Comparison to Existing Implementation

The previous implementation had several limitations:

1. **Limited Dimensionality**: Only tracked requests by client ID
2. **Single Strategy**: Only used a sliding window approach
3. **No Distributed Support**: Didn't work across multiple server instances
4. **Limited Configuration**: Hard-coded rate limits
5. **No Standard Headers**: Didn't provide standard rate limit headers in responses

The new implementation addresses all these limitations and adds new features like payload size limiting and environment-specific configurations.

## Conclusion

This enhanced rate limiting system provides a robust defense against various types of API abuse while maintaining flexibility for legitimate client needs. By implementing multiple dimensions of rate limiting with configurable strategies and actions, it significantly improves the security posture of the Certification Authority API.
