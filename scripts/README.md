# Rate Limit Detection Tools

This directory contains scripts for rate limit detection and testing.

## Dynamic Client Rate Limiting System

The rate limit detection system now supports dynamic client categorization with different rate limits:

### Client Categories

- **Premium Clients**: 30 requests per minute

  - Identified by prefix `premium-` or substring `-prem-`
  - Example: `premium-client1`, `api-prem-client`

- **Standard Clients**: 20 requests per minute (default)

  - All clients without specific categorization
  - Example: `standard-client`, `regular-user`

- **Restricted Clients**: 10 requests per minute
  - Identified by prefix `restricted-` or substring `-rest-`
  - Example: `restricted-client`, `api-rest-user`

### Endpoint-Specific Limits

The system also applies endpoint-specific limits that override client category limits when they are stricter:

- Authentication endpoints: 10 requests per minute
- Certificate management endpoints: 20-30 requests per minute
- Organization management endpoints: 30 requests per minute

### Testing with Different Client Categories

Use the `apiRateLimitAttacker.js` script to test different client categories:

```bash
# Test with a premium client (30 req/min)
node scripts/apiRateLimitAttacker.js --category=premium --requests=100 --interval=50

# Test with a restricted client (10 req/min)
node scripts/apiRateLimitAttacker.js --category=restricted --requests=100 --interval=50
```

## Available Scripts

- `slidingWindowRateLimit.ts`: Core rate limiting implementation with sliding window algorithm
- `apiRateLimitAttacker.js`: Tool to simulate API attacks and trigger rate limiting
- `injectAttackLogs.js`: Utility to inject attack logs into the main detection system
- `viewTimeframeAnalysis.js`: Tool to analyze and visualize rate limit violations
- `fixTimeframeData.js`: Utility to fix issues in timeframe analysis data

## Usage Examples

For full usage instructions, run any script with the `--help` argument:

```bash
node scripts/apiRateLimitAttacker.js --help
node scripts/injectAttackLogs.js help
node scripts/viewTimeframeAnalysis.js --help
node scripts/fixTimeframeData.js --help
```
