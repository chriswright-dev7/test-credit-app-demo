# Secure Form Demo

Simple demo showing a client-side hybrid encryption flow (RSA-OAEP + AES-GCM) with a Node/Express backend and SQLite storage.

Install:

```bash
npm install
```

Run:

```bash
npm start
# then open http://localhost:3000/
```

Notes:
- This is a minimal demo. For production, review security: use HTTPS, proper CORS, key management, authentication, logging, and secure DB storage/encryption at rest.
