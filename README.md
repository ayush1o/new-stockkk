# Fidelity Trading Platform (Backend + DB Integration)

This project now includes a backend API and database-driven business logic for authentication, dashboard data, stock rewards/reviews, spin wheel, notifications, and admin controls.

## Run

```bash
npm start
```

Server runs on `http://localhost:3000`.

## Backend Notes

- Backend implemented in `server.js`.
- Uses built-in Node SQLite (`node:sqlite`) for persistent local database (`fidelity.db`).
- JWT-like token auth (HMAC signed) and password hashing (`crypto.scryptSync`).

## APIs

- `POST /auth/signup`
- `POST /auth/login`
- `GET /dashboard`
- `POST /spin/play`
- `GET /spin/status`
- `POST /review/submit`
- `GET /user/reviews`
- `POST /admin/assign-stock`
- `POST /admin/spin/activate`
- `GET /notifications`

### Extra admin APIs

- `GET /admin/reviews`
- `GET /admin/activity-logs`

## Admin access

`users` table includes `is_admin` (0/1). Promote a user manually in DB for admin routes.
