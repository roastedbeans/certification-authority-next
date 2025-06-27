# MyData API Intrusion Detection System - Certification Authority

## Overview

This repository implements the **Certification Authority** component of a comprehensive **MyData API Intrusion Detection System**. The system provides real-time security monitoring and threat detection for MyData ecosystem APIs through multiple detection algorithms and centralized authentication services.

## System Architecture

The MyData ecosystem consists of three integrated components:

- **🔐 Certification Authority** (this system) - Central authentication and certificate management
- **🏦 Information Provider** - Bank API services for account information
- **🏛️ MyData Operator** - Bank API services for account information

The Certification Authority serves as the **security hub** that:

- Issues OAuth 2.0 tokens for API authentication
- Manages digital certificates for secure data exchange
- Monitors all API traffic in real-time
- Detects security threats using advanced algorithms
- Provides comprehensive security analytics

## 🛡️ Intrusion Detection System Features

### Multi-Algorithm Detection Engine

1. **Signature-Based Detection**

   - Detects known attack patterns using regex matching
   - Covers SQL injection, XSS, XXE, command injection, directory traversal
   - Real-time pattern recognition with 50+ security signatures

2. **Specification-Based Detection**

   - Validates API requests/responses against defined schemas
   - Uses Zod validation for strict type checking
   - Detects parameter tampering, unauthorized access, and data manipulation

3. **Hybrid Detection**

   - Combines both detection methods for maximum coverage
   - Primary specification check, fallback to signature detection
   - Optimized for performance with intelligent layering

4. **Rate Limiting Detection**
   - Dynamic client categorization (Premium, Standard, Restricted)
   - Sliding window algorithm for accurate rate monitoring
   - Endpoint-specific limits with DDoS protection

### 📊 Real-Time Security Dashboard

- **Live Attack Monitoring** - Real-time threat visualization
- **Detection Performance Metrics** - Accuracy, precision, recall analysis
- **Confusion Matrix Analytics** - False positive/negative tracking
- **API Logs Viewer** - Detailed request/response inspection
- **Security Summary** - Attack statistics and trends

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ and npm
- PostgreSQL database
- Docker (optional, for containerized deployment)

### Installation

1. **Clone and setup**

   ```bash
   cd certification-authority-next
   npm install
   ```

2. **Database Configuration**

   ```bash
   # Setup environment variables
   cp .env.example .env

   # Run database migrations
   npx prisma migrate dev

   # Seed initial data
   npm run seedCA
   npm run seedOrg
   ```

3. **Start the application**

   ```bash
   npm run dev
   ```

   Access the Security Dashboard at: `http://localhost:3000/security-dashboard`

## 🔧 Detection System Usage

### Running Detection Algorithms

```bash
# Signature-based detection
npm run signature

# Specification-based detection
npm run specification

# Hybrid detection (recommended)
npm run hybrid

# Rate limiting detection
npm run ratelimit

# Comprehensive analysis
npm run analysis
```

### Attack Simulation & Testing

```bash
# Simulate various attack scenarios
npx tsx scripts/simulations/simulate.ts

# Generate attack traffic for testing
npx tsx scripts/simulations/simulate-invalid-flow.ts

# Rate limit overflow simulation
npx tsx scripts/simulations/simulateRateOverflow.ts
```

## 🏗️ API Endpoints

### Authentication Services

- `POST /api/oauth/2.0/token` - OAuth token issuance
- `POST /api/v2/mgmts/oauth/2.0/token` - Management token endpoint

### Certificate Authority Services

- `POST /api/ca/sign_request` - Certificate signing request (IA102)
- `POST /api/ca/sign_result` - Certificate signing result (IA103)
- `POST /api/ca/sign_verification` - Certificate verification (IA104)

### Organization Management

- `GET /api/v2/mgmts/orgs` - Organization listing and management

## 📈 Security Monitoring

### Detection Performance Metrics

The system tracks comprehensive security metrics:

- **Attack Detection Rate** - Percentage of attacks successfully identified
- **False Positive Rate** - Legitimate requests incorrectly flagged
- **Response Time** - Average detection processing time
- **Threat Coverage** - Types of attacks detected

### Supported Attack Types

- SQL Injection variants
- Cross-Site Scripting (XSS)
- XML External Entity (XXE)
- Command Injection
- Directory Traversal
- Session Hijacking
- Rate Limiting Bypass
- Parameter Tampering
- Token Manipulation

## 🔍 Configuration

### Detection Algorithm Tuning

Modify detection parameters in:

- `scripts/detection-algorithms/security-patterns.ts` - Signature patterns
- `scripts/detection-algorithms/detectionSpecification.ts` - Schema validation rules
- `scripts/detection-algorithms/slidingWindowRateLimit.ts` - Rate limiting configuration

### Client Categories for Rate Limiting

- **Premium Clients**: 30 requests/minute (prefix: `premium-`)
- **Standard Clients**: 20 requests/minute (default)
- **Restricted Clients**: 10 requests/minute (prefix: `restricted-`)

## 📁 Project Structure

```
certification-authority-next/
├── app/                          # Next.js application
│   ├── (routes)/security-dashboard/  # Security monitoring interface
│   ├── _components/              # Security dashboard components
│   ├── _actions/                # Server-side security actions
│   └── api/                     # OAuth and CA API endpoints
├── scripts/                     # Detection and simulation scripts
│   ├── detection-algorithms/    # Core detection engines
│   ├── simulations/            # Attack simulation tools
│   └── analysis/               # Security analytics
├── prisma/                     # Database schema and migrations
└── utils/                      # Security utilities
```

## 🐳 Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# Individual container build
docker build -t mydata-ca-security .
docker run -p 3000:3000 mydata-ca-security
```

## 🤝 Integration with MyData Ecosystem

This Certification Authority integrates with:

- **Information Provider APIs** - Authenticates bank account information requests
- **MyData Operator APIs** - Validates financial data exchange transactions
- **External Security Systems** - Provides threat intelligence and incident response

## 📊 Security Analytics

The system generates detailed security reports including:

- Attack trend analysis
- Detection algorithm performance comparison
- Client behavior analytics
- API usage patterns and anomalies
- Security incident timelines

## 🛠️ Development

### Adding New Detection Rules

1. **Signature-based**: Add patterns to `security-patterns.ts`
2. **Specification-based**: Update schemas in `detectionSpecification.ts`
3. **Rate limiting**: Modify client categories in rate limit configuration

### Testing Detection Algorithms

```bash
# Test individual algorithms
npm run signature
npm run specification
npm run hybrid

# Performance benchmarking
npm run analysis
```

## 📝 License

This project is part of the MyData API security research initiative for developing specification-based intrusion detection systems for web APIs.

---

**Security Notice**: This system is designed for research and development of API security monitoring. Ensure proper configuration and testing before production deployment.
