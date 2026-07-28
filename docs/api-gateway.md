# API Gateway Documentation

## Overview
This setup provides an API gateway for our off-chain SDK services using **Kong (DB-less mode)** and **Prometheus** for analytics.

### Features Included
- **API Versioning**: Enforced via route paths (e.g., `/api/v1`).
- **Authentication**: Validates standard `x-api-key` headers for clients.
- **Rate Limiting**: Limits consumers to 100 requests per minute to prevent abuse.
- **Request Validation & Security**: Enables CORS and bot detection plugins.
- **Analytics**: Exposes metrics to Prometheus at `:8100/metrics`.

## How to Run

1. Navigate to the infra directory:
```bash
cd infra/gateway
```

2. Start the gateway and metrics server:
```bash
docker-compose up -d
```

3. The services are now exposed:
- **Proxy**: `http://localhost:8000`
- **Admin API**: `http://localhost:8001`
- **Prometheus UI**: `http://localhost:9090`

## Developer Portal Setup

Currently, we provide a mock API key for local sandbox testing.
For your apps, pass the API key in your request headers:
```http
GET /api/v1/credentials HTTP/1.1
Host: localhost:8000
x-api-key: sk_test_12345
```

## Adding New Consumers
Edit `infra/gateway/kong.yml` under the `consumers` section and restart the container to apply changes declaratively.
