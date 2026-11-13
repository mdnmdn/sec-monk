# TLS test fixtures

`cert.pem` and `key.pem`: a self-signed ECDSA P-256 certificate for `localhost` / `127.0.0.1` (valid 100 years)
and its private key. **sample: synthetic**, generated for the tests of `secmonk-api` only; the key protects nothing.

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 36500 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
  -addext basicConstraints=critical,CA:FALSE -addext extendedKeyUsage=serverAuth -keyout key.pem -out cert.pem
```
