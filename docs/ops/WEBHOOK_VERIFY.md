# Verifying Kryptkeeper webhook deliveries

Every generic webhook POST carries:

| Header | Value |
|---|---|
| `X-Kryptkeeper-Timestamp` | Unix seconds (decimal), fresh on every attempt |
| `X-Kryptkeeper-Event-Id` | Stable per event across retries; use it to dedupe |
| `X-Kryptkeeper-Signature` | `v1=<hex>[,v1=<hex>]`, HMAC-SHA256(secret, `timestamp + "." + raw body`) |

Sign/verify the exact raw bytes received, never a re-serialised body. If no
`notifications.webhook_secret` is configured the signature header is absent
(timestamp and event id are still sent): receivers MUST reject a missing signature.

Receiver rules: reject if the signature header is absent; reject if
`abs(now - timestamp) > 300s`; accept if ANY `v1=` value matches (constant-time
compare); dedupe on the event id.

## Go

```go
func verifyWebhook(secret string, h http.Header, body []byte, now time.Time) error {
	sigHdr := h.Get("X-Kryptkeeper-Signature")
	if sigHdr == "" {
		return errors.New("missing signature")
	}
	ts := h.Get("X-Kryptkeeper-Timestamp")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("bad timestamp")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > 300*time.Second || d < -300*time.Second {
		return errors.New("stale timestamp")
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "."))
	m.Write(body)
	want := "v1=" + hex.EncodeToString(m.Sum(nil))
	for _, got := range strings.Split(sigHdr, ",") {
		if hmac.Equal([]byte(strings.TrimSpace(got)), []byte(want)) {
			return nil
		}
	}
	return errors.New("signature mismatch")
}
```

## Python

```python
import hmac, hashlib, time

def verify_webhook(secret: bytes, headers, body: bytes, now=None) -> bool:
    sig = headers.get("X-Kryptkeeper-Signature")
    if not sig:
        return False
    ts = headers.get("X-Kryptkeeper-Timestamp", "")
    try:
        ts_int = int(ts)
    except ValueError:
        return False
    if abs((now or time.time()) - ts_int) > 300:
        return False
    want = "v1=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(p.strip(), want) for p in sig.split(","))
```

## Rotating the secret (zero downtime)

1. Set `notifications.webhook_secret_previous` to the current secret, then set
   `notifications.webhook_secret` to the new one (config store or `WEBHOOK_SECRET_PREVIOUS` /
   `WEBHOOK_SECRET` env). Takes effect on the next send, no restart.
2. For 24 hours (from when the previous value was stored; from process start if env-only)
   each delivery carries two signatures, new first. Receivers accept either secret.
3. Update receivers to the new secret, then clear `notifications.webhook_secret_previous`.
   After 24 hours only the new signature is sent regardless.
