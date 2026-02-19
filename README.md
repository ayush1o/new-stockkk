# Fidelity Trading Platform (Backend + DB Integration)

Backend for authentication, stock reward/review engine, spin-wheel logic, admin controls, and notifications.

## Run

```bash
npm start
```

Server runs on `http://localhost:3000`.

## APIs

### User APIs
- `POST /auth/signup`
- `POST /auth/login`
- `GET /dashboard`
- `GET /spin/status`
- `POST /spin/play`
- `POST /review/submit`
- `GET /user/reviews`
- `GET /reviews/history`
- `GET /notifications`

### Admin APIs
- `POST /admin/assign-stock`
- `POST /admin/force-reward`
- `POST /admin/spin/activate`
- `POST /admin/spin/rewards`
- `GET /admin/spin/logs`
- `GET /admin/dashboard`
- `GET /admin/reviews`
- `GET /admin/activity-logs`

## Notes

- Spin rewards are generated only on the server.
- Supports admin forced reward priority for user spin.
- Enforces daily spin limits and request rate-limiting on spin endpoint.
- `users.is_admin` controls access to admin routes.
