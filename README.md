# Atlas: India-first decentralised AI model marketplace (MIT)

Atlas lets Indian creators and MSMEs discover, licence, and run AI models. Buyers pay once for an on-chain licence; the gateway serves inference only to licence holders.

## Architecture
- **Smart contract** (`contracts/AIMarketplace.sol`): listings, licence purchase, 2.5% platform fee, ratings (licensed buyers only, once), pull-payment withdrawals, ReentrancyGuard, custom errors.
- **Gateway** (`backend/server.js`): email/password, Google OpenID Connect, and signed wallet auth, licence-gated downloads and inference, Hugging Face import with licence allowlisting, optional managed inference, creator model verification with licence/model-card declarations and wallet attestations, creator identity/KYC review queues, private licence/provenance evidence, exact-hash provenance checks, optional ClamAV malware scanning, hybrid system-bot moderation with human gates, pending admin moderation, audit records, model comments/favorites, editable creator profiles with avatar uploads and GitHub links, creator dashboards, community posts/replies/likes, reports, takedown/restore actions, usage analytics, Razorpay INR/UPI orders and webhooks, encrypted endpoints, SSRF protection, and rate limits.
- **Frontend** (`frontend/`): Atlas branding, search/filtering, Hugging Face creator studio, verification checklist and MetaMask attestation, ETH wallet checkout, Razorpay UPI checkout, INR pricing, protected inference, creator profile editor, creator dashboard, identity/KYC submission, community tab with discussions and replies, saved models, usage analytics, and a role-protected admin moderation console.

## Run locally
```bash
npm install && (cd frontend && npm install)
npx hardhat node                 # terminal 1
npm test                         # contract tests
npm run deploy                   # terminal 2: writes ABI + address to backend/ and frontend/src/
node backend/mock-model.js       # terminal 3: demo model on :5000
npm run backend                  # terminal 4: gateway on :4000
npm run frontend                 # terminal 5: http://localhost:5173
```
Add the Hardhat network to MetaMask (RPC `http://127.0.0.1:8545`, chain 31337) and import a test key.
Flow: create an Atlas account with Gmail/email and a password, or connect a wallet, upload/import a model, complete its licence and model card, accept creator declarations, sign the exact verification statement in MetaMask, list it after approval, configure a creator or Hugging Face inference endpoint, switch account, buy with INR/UPI or ETH, download or run, rate, comment, and save it. Wallet connection is still required for publishing and on-chain transactions.

## Atlas feature boundaries

- Hugging Face importing records upstream repository, revision, and declared licence; it rejects missing or unapproved licences. After a buyer owns a licence, Atlas can list and stream selected public upstream weight files through a protected gateway without copying them into Atlas storage or overriding their terms.
- Hugging Face inference is an optional server-side adapter and can use managed GPU infrastructure when `HF_API_TOKEN` is configured. A creator endpoint remains the production option for private GPU deployments.
- INR/UPI checkout is implemented as an optional Razorpay integration. The server creates the INR order, verifies the checkout HMAC and captured status, processes webhooks, grants a fiat access record, and records creator/platform INR earnings. Add Razorpay live credentials and complete the provider's KYC/go-live requirements before accepting real money. Fiat access is intentionally separate from the on-chain ETH licence and is labelled in the UI.
- Metadata is held by the gateway for local dev; swap metadata and artifact storage for IPFS, Arweave, or S3-compatible storage in production. Audit the contract and the payment/inference adapters before mainnet.
- **Hybrid creator attestation and moderation:** Atlas does not automatically verify legal ownership. The internal `system:atlas-bot` performs basic format/malware checks, provenance/duplicate checks, low-risk standard-licence decisions, and report triage. It can auto-approve only when every configured low-risk check passes. KYC, licence evidence, custom/commercial listings, disputed provenance, takedowns, role changes, and payments remain human-controlled and are recorded in audit logs. Use `REQUIRE_KYC_FOR_LISTING=true`, `REQUIRE_MALWARE_SCAN=true`, and `AUTO_APPROVE_MODEL_VERIFICATION=false` in production unless the automated policy has been independently reviewed. Configure `ADMIN_WALLET`, review identity/evidence/model queues, and use the report takedown endpoints to hide a disputed model from the catalogue and block gateway downloads/inference. ClamAV can be enabled with the Docker `security` profile; without it, only the basic format scan runs.
- **Takedown boundary:** the gateway moderation state blocks Atlas catalogue, INR orders, downloads, and inference. Existing on-chain model records and licences remain for auditability; a permissionless deployed contract cannot be retroactively erased. If a deployment needs on-chain purchase blocking too, add and audit a contract-level moderator/blocked-model registry before mainnet.

For local development, set `ALLOW_PRIVATE_ENDPOINTS=true` before starting the gateway so the mock model at `http://localhost:5000` is permitted. This flag is ignored in production.

The frontend reads the public catalog from `/api/models`, so browsing does not require an account. Email accounts can save models, comment, buy through configured INR/UPI checkout, and run models after payment. Contract reads, ETH purchases, creator profiles, publishing, and creator earnings still require a connected wallet.

## Production deployment

1. Copy `.env.example` to `.env` and set `NODE_ENV=production`, an HTTPS `PUBLIC_URL`, HTTPS `FRONTEND_URL`/`ALLOWED_ORIGINS`, `RPC_URL`, `CHAIN_ID`, `JWT_SECRET`, and `ENDPOINT_KEY`. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and an exact HTTPS `GOOGLE_REDIRECT_URI` if Google sign-in is enabled. Set `RESEND_API_KEY` and `AUTH_EMAIL_FROM` for email verification and password reset delivery. For managed Hugging Face inference add a fine-grained `HF_API_TOKEN` with inference-provider permission. For INR/UPI add `ENABLE_INR_PAYMENTS=true`, Razorpay credentials, and `RAZORPAY_WEBHOOK_SECRET`. Also set `ADMIN_WALLET=0x...`, `ENABLE_AUTOMATED_MODERATION=false` (or explicitly review and enable it), `AUTO_APPROVE_MODEL_VERIFICATION=false`, `REQUIRE_KYC_FOR_LISTING=true`, `REQUIRE_MALWARE_SCAN=true`, `CLAMAV_HOST=clamav`, and `CLAMAV_PORT=3310`. The configured wallet is bootstrapped as the first `admin` role; use the Admin console to grant `moderator` or `reviewer` roles to trusted wallet addresses or verified email accounts. The hybrid bot is never a login account and cannot grant roles, approve KYC/evidence, take down models, or move payments.
2. Set `SEPOLIA_RPC_URL` and a throwaway `DEPLOYER_KEY` only for the deployment command. Run `npm ci` and `npm run deploy:sepolia`.
3. Confirm that deployment generated `backend/contract.json` and `frontend/src/contract.json`.
4. Remove deployment-only secrets from the runtime environment, then run `docker compose --profile security up -d --build` so the API can use the ClamAV service. The Docker frontend proxies `/api` to the API container; leave `VITE_API` blank for this same-origin setup. Wait for the ClamAV definitions to finish updating before accepting uploads.
5. Put an HTTPS reverse proxy in front of port 8080 for the frontend and port 4000 for the API. The frontend API URL is compiled at image build time from `PUBLIC_URL`.
6. Verify `/api/health`, inspect `docker compose logs api`, configure encrypted backups for `/data` (including private evidence), and do not use mainnet until the contract, KYC/payment, malware, and gateway processes have been independently audited.

## Production hardening (v2)
- **Auth:** email/password accounts use salted scrypt password hashes and generic login errors; Google uses an authorization-code OpenID Connect flow with state, nonce, audience, issuer, and verified-email checks; wallet sign-in uses nonce + domain + chain binding and one-time nonces. Browser sessions use Secure/HttpOnly/SameSite cookies in production, with server-side session expiry/revocation. Google OAuth requires the redirect URI to exactly match the URI registered in Google Cloud.
- **Gateway:** helmet, strict CORS allowlist, global and per-user rate limits, 16kb JSON limit, parameterised SQLite, generic error messages, graceful shutdown, secrets required in production.
- **SSRF:** creator endpoints must be https, private/loopback/link-local ranges blocked at registration and at connect time, no redirects, 15s timeout, 1MB response cap. Endpoint URLs are AES-256-GCM encrypted at rest.
- **Uploads:** authenticated, extension allowlist (no pickle formats), size cap, per-user quota, content-addressed storage, downloads tied to the on-chain content hash and license.
- **Contract:** two-step ownership, renounce disabled, pausable (withdrawals stay open), pull payments, reentrancy guard, custom errors.
- **Deploy:** `Dockerfile.backend`, `frontend/Dockerfile` (nginx with CSP/HSTS), `docker-compose.yml` (read-only FS, no capabilities), CI workflow.

## CI/CD with GitHub Actions

The workflow in `.github/workflows/ci.yml` runs automatically on every pull request and push to `main`/`master`:

- installs dependencies and runs the smart-contract tests;
- compiles the contract and builds the frontend;
- checks backend syntax;
- builds both Docker images;
- publishes `atlas-api` and `atlas-web` to GitHub Container Registry after a successful push to `main`/`master`.

To deploy automatically to a Docker host, prepare the host once:

1. Clone the repository into a deployment directory and create the production `.env` there. Keep runtime secrets such as Google, Razorpay, JWT, RPC, and endpoint keys only on the server.
2. Add these image values to the server `.env`:

```env
ATLAS_API_IMAGE=ghcr.io/YOUR_GITHUB_OWNER/atlas-api:latest
ATLAS_WEB_IMAGE=ghcr.io/YOUR_GITHUB_OWNER/atlas-web:latest
```

3. In GitHub repository Settings → Secrets and variables → Actions, add these repository variables:

```text
ATLAS_PUBLIC_API_URL=
ATLAS_CHAIN_ID=11155111
ATLAS_INR_PER_ETH=0
```

4. Add these repository secrets for the optional SSH deployment step:

```text
DEPLOY_HOST
DEPLOY_USER
DEPLOY_PATH
DEPLOY_SSH_KEY
GHCR_DEPLOY_USER
GHCR_DEPLOY_TOKEN
```

`GHCR_DEPLOY_TOKEN` needs permission to read packages. Leave `ATLAS_PUBLIC_API_URL` blank when the web container proxies `/api` to the API container through the same host. Set it to a public API URL only when the frontend and API are hosted separately. The deploy host must already have Docker, Docker Compose, the repository, and its production `.env`. After that, pushing to `main` runs verification, publishes new images, pulls them on the server, and restarts Atlas. The `workflow_dispatch` button in the Actions tab can trigger the pipeline manually.

### Live demo on Sepolia
1. `cp .env.example .env`, fill secrets and RPC. 2. `npm run deploy:sepolia`. 3. `docker compose up -d --build` behind HTTPS (Caddy/Cloudflare). 4. Use Sepolia test ETH only.
