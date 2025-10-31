# MyData/Open Banking Behavior Rules

### Overview of MyData/Open Banking System Security Requirements

The MyData/Open Banking Certification Authority (CA) system implements security requirements and behavior rules for secure electronic consent and data sharing. These rules define the expected normal behavior of the API endpoints, request/response formats, and protocol flows to ensure compliance with MyData API Specifications. The rules protect against common threats like consent manipulation, API abuse, and protocol violations while enforcing regulatory requirements.

### MyData-Specific Behavior Rules (BR1-BR12)

| Behavior Rule (BR) | MyData Behavior Description | Field/Parameter Requirements | Protocol Impact |
|--------------------|-----------------------------|-----------------------------|-----------------|
| **BR1** | X-API-Tran-ID headers must follow transaction ID format | Header must be exactly AN(25) - 25 alphanumeric characters; consistent across request-response pairs; enables proper transaction correlation | Ensures transaction traceability and prevents ID spoofing |
| **BR2** | API call sequences must follow consent flow progression | Support001 (management token) → Support002 (organization discovery) → IA101 (CA authentication) → IA102 (consent request) → IA103 (consent signing) → IA104 (consent verification) → IA002 (bank data access) | Enforces secure consent lifecycle and prevents consent bypass attacks |
| **BR3** | User consent data must conform to format specifications | user_ci must be base64-encoded and ≤100 characters; real_name ≤30 characters; phone_num must start with +82 prefix and be ≤15 characters total; request_title ≤100 characters; device_code must be PC/TB/MO; device_browser must be WB/NA/HY; return_app_scheme_url ≤100 characters; consent_cnt ≤9999; consent_list array with consent_title ≤100 chars, consent ≤500 chars, consent_len ≤999, tx_id aNS(74) each | Ensures consistent user identification and consent data integrity |
| **BR4** | Support API operations must precede all Certification Authority operations | GET /api/v2/mgmts/orgs and POST /api/v2/mgmts/oauth/2.0/token must complete successfully before any CA endpoints; management token required for organization discovery | Establishes trust anchor and prevents unauthorized CA certificate operations |
| **BR5** | Consent transaction IDs must follow cryptographic format requirements | sign_tx_id aNS(49) - 49 characters alphanumeric+special; cert_tx_id aNS(40) - 40 characters alphanumeric+special; tx_id aNS(74) - 74 characters alphanumeric+special; signed_consent aNS(10000) Base64 url-safe encoded | Enables cryptographic verification and prevents transaction ID manipulation |
| **BR6** | OAuth token scopes must be properly validated and separated | Management tokens (scope='manage') required for Support APIs only; CA tokens (scope='ca') required for consent operations; scope mixing not allowed | Prevents permission escalation and ensures proper separation of administrative vs operational access |
| **BR7** | Consent signing requests must follow successful consent requests | IA103 (/v1/ca/sign_result) must be called only after successful IA102 (consent request); cert_tx_id aNS(40) from IA102 response required as input to IA103 | Ensures consent integrity by requiring prior consent request validation |
| **BR8** | Consent verification must follow successful consent signing | IA104 (sign_verification) must be called only after successful IA103 (sign_result); tx_id aNS(74) from consent list required for verification | Prevents consent forgery by requiring cryptographic proof of prior signing |
| **BR9** | Bank data access must follow successful consent verification | IA002 (bank data access) must be called only after successful IA104 (sign_verification) with flow state 'verified'; verified tx_id aNS(74) and signed_consent aNS(10000) required | Protects user data privacy by ensuring verified consent before data sharing |
| **BR10** | Client credentials must follow format specifications | client_id and client_secret must be exactly aN(50) - 50 alphanumeric characters each; grant_type must be 'client_credentials'; proper scope validation for each API phase | Ensures secure authentication and prevents credential-based attacks |
| **BR11** | API responses must follow standard format | All responses must include rsp_code aN(5), rsp_msg AH(450), and matching x-api-tran-id AN(25) | Ensures consistent API responses and proper transaction correlation |
| **BR12** | Transaction IDs (tx_id) must follow generation format | tx_id must be generated as 'MD'_'business_operator_org_code(10)'_'info_provider_org_code(10)'_'relay_org_code(10)'_'cert_org_code(10)'_'timestamp(YYYYMMDDHHMMSS)(14)'_'serial_number(12)' format | Ensures unique transaction identification and proper audit trails |

### Protocol Flow Requirements

The API enforces the complete consent lifecycle progression:

```
Management Setup → Organization Discovery → CA Authentication → Consent Request → Consent Signing → Consent Verification → Bank Data Access
     ↓              ↓              ↓               ↓             ↓           ↓               ↓
  Support001      Support002      IA101          IA102         IA103       IA104           IA002
```

#### Critical Flow Dependencies
- **Management Phase**: Support001 and Support002 must complete before any CA operations to establish trust anchor
- **Authentication Phase**: IA101 CA token acquisition required before consent operations (IA102-IA104)
- **Consent Phase**: IA102 → IA103 → IA104 sequence is mandatory for valid consent
- **Access Phase**: IA002 bank data access requires successful IA104 consent verification to protect user privacy

### Field Format Requirements

#### Transaction Identification
- **X-API-Tran-ID**: AN(25) - exactly 25 alphanumeric characters for transaction correlation
- **sign_tx_id**: aNS(49) - 49-character signing transaction identifier (alphanumeric + special characters)
- **cert_tx_id**: aNS(40) - 40-character certificate transaction identifier (alphanumeric + special characters)
- **tx_id**: aNS(74) - 74-character transaction identifier with format: 'MD'_'business_operator_org_code(10)'_'info_provider_org_code(10)'_'relay_org_code(10)'_'cert_org_code(10)'_'timestamp(YYYYMMDDHHMMSS)(14)'_'serial_number(12)'

#### User Consent Data Structure
- **user_ci**: Base64-encoded user identification information (≤100 characters)
- **real_name**: User's real name (≤30 characters)
- **phone_num**: Mobile number starting with +82 (≤15 characters total)
- **device_code**: PC (Personal Computer), TB (Tablet), MO (Mobile)
- **device_browser**: WB (Web Browser), NA (Native App), HY (Hybrid App)
- **consent_list**: Array of consent items with title (≤100 chars), content (≤500 chars), and transaction IDs

#### Consent Validation Rules
- **consent_cnt**: Number of consent items (≤9999)
- **consent_len**: Length of individual consent content (≤999 characters)
- **signed_consent**: aNS(10000) - Base64 url-safe encoded signed consent data (≤10000 characters)
- **consent_type**: Single character consent type identifier
- **return_app_scheme_url**: Optional app return URL (≤100 characters)

### Trust Establishment Sequence

#### Phase 1: Management Token Acquisition
```
POST /api/v2/mgmts/oauth/2.0/token
Content-Type: application/x-www-form-urlencoded
Body: grant_type=client_credentials&client_id=<aN(50)>&client_secret=<aN(50)>&scope=manage
Response: Bearer token with 'manage' scope and rsp_code, rsp_msg
```

#### Phase 2: Organization Discovery
```
GET /api/v2/mgmts/orgs
Authorization: Bearer <manage_token>
X-API-Tran-ID: <AN(25)>
Response: Organization list with org_cnt and org_list array
```

#### Phase 3: CA Authentication
```
POST /api/oauth/2.0/token
Content-Type: application/x-www-form-urlencoded
Body: grant_type=client_credentials&client_id=<aN(50)>&client_secret=<aN(50)>&scope=ca
Response: Bearer token with 'ca' scope
```

#### Phase 4-6: Consent Lifecycle
Consent request (IA102) → Consent signing (IA103 /v1/ca/sign_result) → Consent verification (IA104) with proper transaction ID progression and cryptographic validation.

### Standard Response Format

All API responses must include standard response fields:
- **rsp_code**: aN(5) - exactly 5 alphanumeric characters for response code
- **rsp_msg**: AH(450) - response message up to 450 characters
- **x-api-tran-id**: AN(25) - matching request transaction ID for correlation

This behavior rules framework ensures compliance by enforcing the specific field formats, transaction ID structures, and consent flow sequences, protecting against consent manipulation and ensuring secure data sharing between users, certification authorities, and financial institutions.
