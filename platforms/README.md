# Generated API platforms

These directories provide hit commands and request/response contracts generated from the canonical public OpenAPI specifications used by Solutions Engineering.

Sources:

- [`afterpay/afterpay-fern-config`](https://github.com/afterpay/afterpay-fern-config) at `adb6d12935a2c4a081af2bec4e92fa28a23fc3e9` for Direct and Agency APIs.
- [`cashapp/cash-app-fern-config`](https://github.com/cashapp/cash-app-fern-config) at `74d6eb6c9de46a0c8f9a1478d9d260a0e6f20a87` for Cash App Pay Partner API.

| Platform | Operations | JSON request templates | Authentication |
| --- | ---: | ---: | --- |
| Afterpay Direct API | 41 | 24 | Basic auth |
| Afterpay Agency API | 16 | 7 | HMAC-SHA256 request signing |
| Cash App Pay Partner API | 80 | 32 | Client credentials + HMAC-SHA256 request signing |

Each platform contains:

- `.hit/config.json`: every supported HTTP operation from its OpenAPI specs.
- `bodies/`: editable JSON templates for operations with JSON request bodies.
- `catalog.json`: operation metadata plus request and response schemas/statuses.
- `openapi/`: the source contracts, including component schemas.

Regenerate all derived files after updating the source contracts:

```bash
ruby scripts/generate_platforms.rb
```

## Usage

Select the platform directory because hit loads `.hit/config.json` from the current directory. The `runtime` environment only needs to be selected once.

### Afterpay Direct API

```bash
cd ~/Development/hit-cli/platforms/direct-api
hit env use runtime
swenv afterpay-cafe-us sbox

hit run configuration get-configuration
hit run checkouts create-checkout-1 \
  --body-file bodies/checkouts/create-checkout-1.json
```

Direct API reads `AFTERPAY_API_URL`, `AFTERPAY_MERCHANT_ID`, and `AFTERPAY_MERCHANT_SECRET`.

### Afterpay Agency API

```bash
cd ~/Development/hit-cli/platforms/agency-api
hit env use runtime
swenv <agency-credential-context> sbox

hit run partner create-onboarding \
  --body-file bodies/partner/create-onboarding.json
```

Agency API reads `AGENCY_BASE_URL`, `AGENCY_API_KEY`, and `AGENCY_SHARED_SECRET`. Hit generates the current request timestamp and HMAC signature from the final URL and body.

### Cash App Pay Partner API

```bash
cd ~/Development/hit-cli/platforms/cash-app-pay-partner-api
hit env use runtime
swenv <cash-app-pay-credential-context> sbox

hit run network-api list-payments --query limit=50
hit run network-api create-payment \
  --body-file bodies/network-api/create-payment.json
```

Cash App Pay reads `CASH_API_URL`, `CASH_CLIENT_ID`, `CASH_API_KEY`, `CASH_CLIENT_SECRET`, and `CASH_REGION`. Hit signs the final method, path/query, canonical headers, and body digest.

Use repeatable options for parameters not baked into a generated command:

```bash
hit run network-api list-payments \
  --query limit=50 \
  --query status=AUTHORIZED \
  --header 'Idempotency-Key:example-id'
```

Request templates intentionally contain visible placeholders such as `<merchant_id>`. Edit a template copy before sending it. Responses remain unmodified; use `--json` for structured status, headers, and body output.
