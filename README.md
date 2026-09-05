# Keerthan Tunkoju — Portfolio (Frontend + Backend)

A full-stack personal portfolio: the same single-page frontend you already had, now backed
by a real Node/Express API for authentication, content storage, file uploads, and the
contact form.

## What changed from the artifact version

The page itself (layout, styling, sections) is unchanged. What's different is *where the
data lives and how the editor is protected*:

| | Before (artifact) | Now (this project) |
|---|---|---|
| Content storage | Browser storage API (Claude-only) | JSON files on your server, via a real API |
| Editor login | Client-side passphrase (anyone could bypass it) | Server-checked password, bcrypt-hashed, JWT session |
| Photo / resume uploads | Base64 embedded in the saved data | Uploaded to `/uploads` on the server, referenced by URL |
| Contact form | Opened the visitor's email client | POSTs to the server; stored + optionally emailed to you |

## Project structure

```
backend/
  server.js              Express API (auth, portfolio CRUD, uploads, contact)
  package.json
  .env.example            Copy to .env and fill in as needed
  data/
    portfolio.seed.json   Initial content, extracted from your resume
    portfolio.json         (created on first run — the live content)
    auth.json               (created on first run — your hashed password)
    contacts.json           (created on first run — contact form messages)
  uploads/                Uploaded photos, project images, and your resume PDF
  public/
    index.html            The frontend (your original page, now calling the API)
```

## Running it locally

Requires Node.js 18+.

```bash
cd backend
npm install
cp .env.example .env      # optional — defaults work fine for local use
npm start
```

Then open **http://localhost:4000** in your browser. That's it — the frontend is served
by the same server, so there's no separate frontend build step or CORS setup needed.

## Setting up the editor

1. Click the pencil (✎) icon in the nav.
2. The first time, you'll be asked to **create a password** (minimum 6 characters). This
   is checked by the server and hashed with bcrypt — it is real authentication, not a
   client-side trick.
3. From then on, that password logs you in. Sessions last 7 days; you can log out any
   time from the new **Account** tab in the editor, which also lets you change your
   password.

If you forget your password, stop the server and delete `data/auth.json`, then restart —
you'll be asked to set a new one. (There's no self-service "forgot password" flow since
there's no email-sending identity to reset it through until you configure one.)

## The Messages tab

Contact-form submissions are stored server-side and listed in a new **Messages** tab in
the editor, newest first, with read/unread status and delete.

## Sending contact-form emails (optional)

By default, messages are just stored — you'll read them in the Messages tab. If you'd
also like them emailed to you, fill in the SMTP settings in `.env`:

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASS=your-app-password     # not your regular password — use an app password
CONTACT_TO_EMAIL=you@gmail.com
```

Any SMTP provider works (Gmail, Outlook, SendGrid, Mailgun, etc.) — these are just the
standard nodemailer settings. If sending fails for any reason, the message is still saved
and visible in the Messages tab; nothing is lost.

## Uploads

Profile photo, project images, and your resume PDF are uploaded via the editor and stored
in `backend/uploads/`, served at `/uploads/<filename>`. Limits: 8MB per file; images
(JPG/PNG/WEBP/GIF) and PDF only.

## Deploying it for real

This is a normal Node/Express app, so it runs on any Node host — Render, Railway, Fly.io,
a VPS, etc. A few things to set up wherever you deploy:

- **Persistent disk**: `data/` and `uploads/` need to survive restarts and redeploys.
  Most platforms (Render, Railway, Fly) offer a "persistent volume" or "disk" — mount it
  at the `backend` directory, or point `DATA_DIR`/`UPLOADS_DIR` at it (see `server.js` if
  you want to make those paths configurable via env vars for your host).
- **JWT_SECRET**: set this explicitly in production (see `.env.example`) so sessions
  don't invalidate if the server restarts without persistent storage for the auto-generated
  secret file.
- **HTTPS**: run behind your host's TLS termination (virtually all of the platforms above
  do this for you automatically).
- **Custom domain**: point your domain at the host once deployed; no code changes needed
  since the frontend calls the API via a relative path (`/api/...`).

## Security notes

- Passwords are bcrypt-hashed (cost factor 12) — never stored in plaintext.
- Login and contact-form submission are rate-limited to reduce brute-force and spam risk.
- Basic security headers are set via `helmet`.
- The admin API rejects any request without a valid, unexpired JWT.
- Uploads are restricted by MIME type and size, and given randomized filenames.

This is a solid setup for a personal site, but it's a single-admin system with no
multi-user roles, audit log, or automated backups — worth keeping in mind if you ever
need more than "just me, editing my own portfolio."
