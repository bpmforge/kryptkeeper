-- Purpose: persist an endpoint's on-the-wire crypto posture, including
-- whether ML-KEM hybrid key exchange was negotiated or offered, the live
-- post-quantum signal the cert inventory cannot see. Discovery computes it
-- from the capture handshake via scanner.PostureProber, stored as JSON.
-- Nullable, populated on the next scan.
-- Depends on: 000003
-- Rollback pair: 000056_endpoint_crypto_posture.down.sql

ALTER TABLE endpoints ADD COLUMN crypto_posture TEXT;
