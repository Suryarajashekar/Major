# Atlas API

The gateway uses JSON responses and bearer tokens returned by the email or wallet authentication endpoints.

## Public endpoints

### `GET /api/health`

Returns gateway, chain, and contract health.

### `GET /api/models?offset=0&limit=24&q=&tag=&source=`

Returns a bounded page of on-chain models with optional search, tag, and source filters. `limit` is capped at 50.

### `GET /api/models/:id`

Returns one on-chain model.

### `GET /api/metadata/:id`

Returns a generated model metadata manifest.

### `GET /api/models/:id/comments`

Returns the community discussion for a model.

### `GET /api/payments/quote?wei=...`

Returns an optional INR display quote. When Razorpay is configured, use the checkout endpoints below for real INR/UPI settlement.

## Authentication endpoints

### `GET /api/nonce`

Returns a one-time sign-in nonce valid for five minutes.

### `POST /api/auth/register`

Creates an Atlas email/password account and returns a short-lived JWT. Passwords must be 8 to 128 characters; the server stores only a salted scrypt hash.

```json
{ "email": "creator@gmail.com", "password": "your-password" }
```

### `POST /api/auth/login`

Signs in an existing Gmail/email account. Failed attempts return the same generic error for unknown emails and wrong passwords.

### `GET /api/auth/google`

Starts Google OpenID Connect sign-in. Configure `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI` on the API server. The callback validates the OAuth state, ID-token audience/issuer/nonce, and verified email before creating an Atlas session.

### `GET /api/auth/google/callback`

Google's registered redirect endpoint. On success, it creates the secure Atlas session cookie and redirects to the configured frontend.

### `POST /api/auth/password-reset/request`

Requests a password-reset email. The response is intentionally generic so it does not reveal whether an email is registered.

### `POST /api/auth/password-reset/confirm`

Consumes a one-time reset token and sets a new password.

### `GET /api/auth/verify-email?token=...`

Consumes a one-time email-verification token and redirects to the frontend.

### `POST /api/auth/logout`

Revokes the current server-side session and clears the HttpOnly cookie.

### `GET /api/auth/me`

Returns the identity represented by the bearer token.

### `POST /api/login`

Body:

```json
{
  "message": "Atlas sign-in...",
  "signature": "0x..."
}
```

The message must contain the configured frontend host and chain ID. The response contains a short-lived JWT.

## Creator endpoints

All creator endpoints require an authenticated session cookie or `Authorization: Bearer <token>` from a connected wallet. Email/Google accounts can authenticate for buyer features, but they cannot publish models or configure creator endpoints because those actions write or control on-chain creator assets.

### `POST /api/upload`

Multipart upload of one `.onnx`, `.safetensors`, `.gguf`, or `.tflite` file. Atlas validates the filename, size, extension, and basic SafeTensors/GGUF format, then returns the SHA-256 `contentHash` and protected `artifactURI`. If `CLAMAV_HOST` is configured, the file also passes through ClamAV. Production should set `REQUIRE_MALWARE_SCAN=true`; otherwise the API reports that only the basic scan ran.

### `POST /api/metadata`

Creates a metadata manifest. When `artifactHash` is supplied, the artifact must belong to the authenticated wallet. Set `priceInr` to publish an INR/UPI price for Razorpay checkout. A production listing should include `license`, `licenseUrl`, and `modelCard` fields.

### `POST /api/model-verifications/prepare`

Creates a pending verification request for a creator-owned manifest. The request requires an approved licence, an HTTPS proof URL, model card (`purpose`, `trainingData`, `limitations`, and `intendedUsers`), an optional provenance URL, and three declarations: ownership/distribution rights, safety-risk disclosure, and responsibility for the submitted information. Standard licences are restricted to canonical licence pages; Hugging Face imports must use the exact upstream model-card URL. Atlas checks exact SHA-256 duplicates and records a provenance result, but it does not make a semantic plagiarism or legal-ownership determination. With `REQUIRE_KYC_FOR_LISTING=true`, the creator must have a verified identity case. The response contains an exact human-readable `message` for the creator to sign with MetaMask.

### `POST /api/model-verifications/:id/attest`

Accepts `{ "signature": "0x..." }`, recovers the signing wallet, and records the signed attestation. Commercial, proprietary, and custom licences must have a private licence evidence upload and moderator approval. When `ENABLE_AUTOMATED_MODERATION=true`, the internal `system:atlas-bot` can auto-approve only a clean standard case whose provenance, scan, identity policy, and evidence checks pass; otherwise the response is `pending_review`. The bot cannot approve KYC/evidence, grant roles, take down models, or handle payments. Production should normally set `ENABLE_AUTOMATED_MODERATION=false` and `AUTO_APPROVE_MODEL_VERIFICATION=false` until the policy is independently reviewed.

### `GET /api/model-verifications/:id`

Returns the authenticated creator's verification status without exposing the signature or declarations.

### `POST /api/model-verifications/:id/evidence`

Multipart upload with `file` and `kind=license|provenance`. Evidence is stored in the private `/data/evidence` volume and only its hash/status is returned to the creator. Admins review evidence with `POST /api/admin/model-evidence/:id/review` and can download it through the admin-only evidence route.

### `GET/POST /api/creator-identity`, `POST /api/creator-identity/document`

Submit a creator identity/KYC case and a private PDF/image document. Atlas hashes the name, provider reference, and document; it does not store raw identity numbers in the database. The case remains `pending_review` until an admin or regulated KYC provider reviews it. Admin routes are `GET /api/admin/creator-identities`, `GET /api/admin/creator-identities/:wallet/document`, and `POST /api/admin/creator-identities/:wallet/review`.

### `GET /api/admin/model-verifications?status=pending_review`

Admin-only moderation queue. The request must be authenticated by an active `admin`, `moderator`, or `reviewer` role. `ADMIN_WALLET` is bootstrapped as the first `admin` role.

### `GET /api/admin/me`, `GET /api/admin/overview`

Return the authenticated admin role, permissions, moderation queue counts, and hybrid-automation status.

### `GET /api/admin/automation`

Returns the system-bot policy, its allowed capabilities, and recent automation events. This endpoint is for human administrators; `system:atlas-bot` is an internal audit actor and cannot log in.

### `GET/POST/DELETE /api/admin/roles`

Administrator-only role management. The first administrator can grant or revoke `admin`, `moderator`, or `reviewer` roles for wallet addresses or verified email subjects. Moderators can review reports and takedowns; reviewers can review identity, evidence, and model verification queues.

### `POST /api/admin/model-verifications/:id/review`

Admin-only review using `{ "status": "approved" | "rejected", "reason": "..." }`. Rejections require a reason and are written to the verification audit log.

### `POST /api/admin/model-verifications/:id/provenance-review`

Admin-only exact/provenance review using `{ "status": "passed" | "rejected", "reason": "..." }`. This is the human review step for duplicate-hash flags and submitted provenance evidence; it is not an automated plagiarism verdict.

### `GET /api/admin/model-verifications/:id/audit`

Returns the append-only verification preparation, attestation, and moderation events for an admin audit trail.

### `POST /api/huggingface/import`

Inspects a Hugging Face repository, requires a declared approved licence, and creates an Atlas metadata manifest pinned to the upstream revision. Atlas does not copy upstream weights.

### `GET /api/huggingface/files/:id`

Requires a valid Atlas session and an on-chain or verified INR licence. Returns the public weight files available in the imported Hugging Face repository.

### `GET /api/huggingface/download/:id?file=...`

Requires a valid licence and streams the selected upstream weight file through Atlas. The file is not stored in Atlas; access is checked before the upstream Hugging Face response is streamed to the buyer.

### `POST /api/endpoint/:id`

Stores an encrypted inference endpoint for the on-chain model creator. Use `{ "provider": "huggingface", "repo": "org/model" }` for managed Hugging Face inference, or `{ "provider": "creator", "url": "https://..." }` for a private GPU endpoint. Production URLs must use HTTPS and public DNS resolution.

### `POST /api/payments/order`

Creates a server-owned Razorpay INR order from the model's published `priceInr` metadata. The browser must never choose the amount.

### `POST /api/payments/verify`

Verifies the Razorpay checkout HMAC, retrieves the provider payment, requires `captured` status, and grants fiat access to the authenticated Atlas account. Creator earnings remain associated with the publishing wallet.

### `POST /api/payments/webhook`

Validates `x-razorpay-signature` with `RAZORPAY_WEBHOOK_SECRET` and processes `payment.captured`/`payment.failed` events. Configure this URL as `https://your-api.example/api/payments/webhook`.

### `GET /api/payments/access`

Returns model access granted through verified INR payments.

### `GET /api/fiat-earnings`

Returns the authenticated creator's INR gross sales, Atlas fee, and pending creator net ledger. Payouts are handled through the merchant/provider settlement process and are not silently sent from the blockchain contract.

### `GET /api/favorites`, `POST/DELETE /api/favorites/:id`

Manage saved models for the authenticated wallet.

### `POST /api/models/:id/comments`

Adds a moderated-length community comment.

### `GET /api/creator-profile`

Returns the connected wallet's creator profile.

### `POST /api/creator-profile`

Stores a creator display name, bio, language, MSME focus, HTTPS website, GitHub link, and optional HTTPS profile-photo URL.

### `POST /api/creator-profile/avatar`

Accepts a `multipart/form-data` field named `avatar`. PNG, JPEG, WebP, and GIF images up to 2 MB are stored in the Atlas data volume and served through the creator-avatar route.

### `GET /api/creator-dashboard`

Returns the connected creator's profile, on-chain models and sales, withdrawable ETH earnings, and INR earnings ledger.

### `GET /api/community/posts`

Returns public community posts with author profile, likes, and reply counts.

### `POST /api/community/posts`

Creates an authenticated community post. Supported categories are `General`, `Model showcase`, `MSME`, `Help`, and `Jobs`.

### `GET /api/community/posts/:id/replies`, `POST /api/community/posts/:id/replies`

Reads or adds replies to a community post.

### `POST/DELETE /api/community/posts/:id/like`

Adds or removes the authenticated user's like from a community post.

### `POST /api/reports`

Creates a moderation report for a model. The hybrid bot classifies it as normal, medium, or high risk and routes high-risk reports to human review without automatically taking down the model. Administrators can inspect reports with `GET /api/admin/reports` when `ADMIN_WALLET` is configured.

### `POST /api/admin/reports/:id/review`

Admin-only action using `dismiss`, `resolve`, `takedown`, or `restore`. Takedown hides the model from the public catalogue and blocks new API purchases, downloads, and inference. It preserves on-chain history and existing licence records for auditability. Direct manual actions are also available at `POST /api/admin/models/:id/takedown` and `POST /api/admin/models/:id/restore`; audit history is available from `GET /api/admin/models/:id/moderation-audit`.

Atlas should be described as providing **creator attestation and moderation**, not automatic legal ownership verification. Human review, KYC-provider checks, provenance services, malware operations, notices, appeals, and legal takedown decisions remain operational responsibilities for a production operator.

## Licensed user endpoints

### `GET /api/artifact/:hash?model=:id`

Downloads a creator-uploaded artifact only when the hash matches the on-chain model, the artifact belongs to the on-chain creator, and the caller owns the license. Imported Hugging Face models use the upstream routes above instead.

### `POST /api/infer/:id`

Runs inference for a licensed user. Current input format:

```json
{
  "input": "text sent to the model endpoint"
}
```

Inputs are forwarded to the creator or Hugging Face inference endpoint. Deployments must publish their retention and privacy policy. Usage counts are available from `GET /api/usage`.
