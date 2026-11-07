# EasyAPI Backend

REST API for **EasyAPI**, an API operations workspace. Handles authentication, workspaces and team sharing, request logs, profile photos and user preferences.

The web app lives in a separate repository: **EasyAPI-Frontend**.

## Tech stack

Node.js, Express, Mongoose (MongoDB), JWT, Google Sign-In verification, multer (memory storage) and Cloudinary for profile photos.

## Getting started

### Prerequisites

- Node.js (LTS) and pnpm through corepack (`corepack pnpm ...`)
- A MongoDB database (local or Atlas)
- A Cloudinary account (cloud name, API key, API secret)
- Optional: a Google OAuth client ID for Google sign-in

### Clone

```bash
git clone https://github.com/aditya79373/EasyAPI-Backend.git
cd EasyAPI-Backend
```

### Install and run

```bash
corepack pnpm install
node server.js
```

The whole server is in a single file, `server.js`, in the repository root.

If everything is set up correctly, the server connects to MongoDB and starts listening on `PORT`.

### Environment variables

Create a `.env` file in the project root:

```env
# Cloudinary (profile photos)
CLOUDINARY_CLOUD_NAME=
CLOUD_API_KEY=your_api_key
CLOUD_API_SECRET=your_api_secret

# Check the exact names used in server.js and adjust if they differ
MONGO_URI=mongodb+srv://...
JWT_SECRET=a-long-random-string
PORT=5000
GOOGLE_CLIENT_ID=your_google_client_id
```

Never commit `.env`. Uploads go through the backend with the API key and secret; no unsigned upload preset is used.

## API overview

All authenticated routes expect `Authorization: Bearer <token>`.

| Method | Route | Purpose |
| --- | --- | --- |
| POST | `/api/auth/register` | Create account and workspace |
| POST | `/api/auth/login` | Sign in |
| POST | `/api/auth/google` | Google sign-in |
| POST | `/api/auth/forgot-password` | Send a 6-digit reset code |
| POST | `/api/auth/verify-otp` | Verify the code, returns a reset token |
| POST | `/api/auth/reset-password` | Set a new password |
| GET | `/api/auth/me` | Current user, avatar and preferences |
| PUT | `/api/auth/profile` | Update name or workspace, remove avatar |
| POST | `/api/auth/avatar` | Upload profile photo (multipart, field `avatar`, max 3 MB) |
| PUT | `/api/auth/password` | Change password |
| PUT | `/api/auth/prefs` | Monitoring and log preferences |
| GET / DELETE | `/api/requests` | List or delete request logs |
| GET | `/api/team` | Team members and invites |

## Workspace sharing

- A signed-in user can be invited to another user's workspace. The invite is stored as an `Invite` and becomes a `Link` once accepted.
- When the client sends an `x-workspace` header, the `scope` middleware resolves it to the workspace owner and the request reads **that owner's** data.
- Linked workspaces are always **Viewer** (read-only): write requests are rejected.
- Invite statuses: `Pending`, `Active`, and `Declined` (shown as "Rejected" in the UI). A removed member can be invited again.

## Deployment (Render)

1. Create a new **Web Service** from this repository.
2. Build command: `corepack pnpm install`. Start command: `node server.js`.
3. Add the same environment variables in the service settings.
4. Allow your frontend's URL in CORS and set the frontend's `VITE_API_URL` to this service's URL.
