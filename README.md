# Fava Radio 2.0 — Android-ready project + cloud backend

This repository is a working **development scaffold** for Fava Radio: a Persian RTL PTT-style interface, a Node.js API, PostgreSQL persistence, JWT login, invite-only registration, channel management, basic admin permissions, Socket.IO messaging, and LiveKit token issuance for real-time audio/video.

> Important: this is not a production-certified application and no server has been deployed from this package. LiveKit media, Android device permissions, uploads, push notifications, and multi-device end-to-end tests must be configured and tested before real operational use. The interface includes a message UI; image/video uploads are not yet implemented. Never use it for emergency-critical communication until tested.

## Stack
- Android packaging: Capacitor + Android Gradle project generated in GitHub Actions (Java 17)
- Client: React + Vite + `livekit-client`
- API/realtime events: Node.js + Express + Socket.IO
- Database: PostgreSQL
- Password storage: bcrypt; signed access tokens: JWT
- Media: LiveKit Cloud credentials are kept only on the server

## Local development (Windows CMD)
Install Node.js 20+ and Java 17 for Android builds.

1. Create a PostgreSQL database.
2. Copy `server/.env.example` to `server/.env` and set `DATABASE_URL`, a random `JWT_SECRET` of at least 32 characters, `ADMIN_BOOTSTRAP_PASSWORD` (12+ characters), and a private `INVITE_CODE`.
3. Add the LiveKit server URL/API key/API secret to the environment when you are ready to test live media.
4. From this folder run:

```cmd
npm install
npm --prefix server install
npm --prefix web install
npm run dev
```

Web UI: `http://localhost:5173`; API: `http://localhost:10000/health`.

## Deploy on Render
1. Push this folder to a GitHub repository.
2. In Render, create a PostgreSQL database. The free PostgreSQL tier has a 30-day lifetime, so it is for testing only; upgrade or use another durable Postgres provider before real use.
3. Create a Web Service connected to the repository and use the `render.yaml` settings (or `npm install && npm --prefix web install && npm --prefix server install && npm --prefix web run build` as build command; `npm --prefix server start` as start command).
4. Set `DATABASE_URL` to the database's **internal** connection string, and set strong values for `ADMIN_BOOTSTRAP_PASSWORD` and `INVITE_CODE`.
5. Create a LiveKit Cloud project and set `LIVEKIT_URL`, `LIVEKIT_API_KEY`, and `LIVEKIT_API_SECRET`. Never expose the API secret in the app or commit `.env` files.
6. After the first successful deployment, log in with username `admin` and the bootstrap password. Change that password and keep the invite code private.

Render free web services sleep after inactivity and may take about a minute to wake. Free Render Postgres expires after 30 days. This setup is a demo/test environment, not a dependable always-on radio service.

## Android APK via GitHub Actions
The included workflow at `android-wrapper/.github/workflows/build-apk.yml` is a guide. Move/copy it to the repository's `.github/workflows/build-apk.yml` before pushing. It builds the web assets, generates the native Android project using Capacitor, and uploads a debug APK as a workflow artifact. The APK needs a deployed HTTPS API URL baked into `VITE_API_URL` at web-build time for devices to use the cloud service. For this, add a build environment variable `VITE_API_URL=https://YOUR-SERVICE.onrender.com` before `npm run build` in the workflow. A release APK requires signing configuration.

## Current capability status
- Included in code: invite-gated registration endpoint, login, bcrypt password hashing, JWT auth, user roles, basic permission updates, channel CRUD API, authenticated sockets, text messages, LiveKit token endpoint, PTT/audio/video client hooks.
- Not complete: attachment upload/storage and thumbnail generation, camera/microphone behavior verification on physical devices, private direct messaging UI, channel member-management UI, password reset/rotation UI, push notifications, account recovery, production rate limiting/audit log, Android release signing, load/security testing.
