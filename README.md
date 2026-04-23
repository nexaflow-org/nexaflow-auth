# finagent-auth

`finagent-auth` is the FastAPI authentication service for the FinAgent platform.

## Gateway Deployment Notes

This service is designed to run behind the platform gateway. Browsers should call the gateway endpoint, and the gateway proxies auth requests to this service on its internal port.

- Internal service port: `GATEWAY_INBOUND_PORT=8001`
- Health endpoint: `GET /api/v1/auth/health`
- Auth routes remain available under `/api/v1/auth/*`

## Environment

Keep the existing `MYSQL_*` variables as-is for database connectivity. Set `ALLOWED_ORIGINS` to the browser-facing gateway origin, plus any local development origins that should be allowed to send credentials.

Example:

```env
ALLOWED_ORIGINS=http://localhost:8080,http://localhost:5173
GATEWAY_INBOUND_PORT=8001
```

## Operational Notes

- `GET /api/v1/auth/health` is unauthenticated and returns `{"status": "ok"}` with HTTP `200`.
- Rate limiting uses `X-Forwarded-For` when present so limits apply to the real client IP instead of the gateway IP.
- The Docker image already runs as a non-root user and includes a container healthcheck for `/api/v1/auth/health`.
