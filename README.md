# LinkPulse

LinkPulse is a Flask URL shortener and campaign-link analytics app backed by Supabase Postgres.

## Run locally on Windows

1. Install Python 3.14.
2. Create and activate a virtual environment, then install dependencies:

   ```powershell
   py -3.14 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env`. Set `DATABASE_URL` to your Supabase Postgres connection string and replace `SECRET_KEY` with a private random value. Keep `.env` private.
4. Start the local server:

   ```powershell
   .\.venv\Scripts\python.exe app.py
   ```

5. Open `http://127.0.0.1:5000/register` to create an account.

The Supabase project must already have the LinkPulse tables (`app_users`, `links`, and `click_events`).

## Admin account

Create an admin account from the project directory:

```powershell
.\.venv\Scripts\flask.exe --app app seed-admin
```

The command prompts for the email and a hidden password. Admin passwords must be 12–128 characters.

## Sample demo data

After creating the account that should own the examples, add three sample links and 16 sample visits:

```powershell
.\.venv\Scripts\flask.exe --app app seed-demo
```

The command prompts for that account's email. It creates `demo-event`, `demo-launch`, and `demo-signup` links with example.com destinations and synthetic click details. It does not create users or campaigns. Run it only once; it stops without changes if any sample short code already exists.

## Main routes

- `/register` and `/login` — account access
- `/dashboard` — create and manage short links
- `/<short_code>` — redirect and record a visit
- `/links/<link_id>/analytics` — per-link activity report
- `/health/database` — database connection status

## Configuration

The app reads `DATABASE_URL` and `SECRET_KEY` from the environment. Set `SESSION_COOKIE_SECURE=true` when serving over HTTPS. Never commit `.env` or paste its values into chat.

For a Linux host, the included `Procfile` starts the app with Gunicorn. Configure `DATABASE_URL`, `SECRET_KEY`, and `SESSION_COOKIE_SECURE=true` in the hosting provider's private environment settings. The host must be able to reach the Supabase Postgres endpoint.

## Deploy on Render

The root `render.yaml` defines a Free web service in Singapore, uses the `main` branch, and deploys new commits automatically. Create a Render Blueprint from this repository. During the initial setup, enter the Supabase Postgres connection string only in Render's private prompt for `DATABASE_URL`; Render generates `SECRET_KEY` and enables secure session cookies.

## Testing guide

Live app: `<YOUR_RENDER_APP_URL>` (replace this placeholder with the public Render URL; do not add account passwords or secrets to this public README).

Render's free service may take a little while to wake after being idle. Wait for the page to finish loading before testing. The database must be reachable and contain the `app_users`, `links`, and `click_events` tables.

Suggested judge path:

1. Register or sign in with a regular judge account.
2. Create a short link using a valid `https://` destination, open it, then view its report.
3. Try an invalid destination and a duplicate short code; both should be rejected.
4. Import a UTF-8 CSV with `destination_url` and optional `short_code` columns. Include a valid row, an invalid URL, and a duplicate code to see row handling.
5. Sign in as an admin and disable a link. Opening it should show HTTP 410; its analytics should remain available.
6. As a regular user, attempting the admin disable action should be rejected with HTTP 403.

Admin accounts are created with `flask --app app seed-admin`. Demo data can be added for an existing account with `flask --app app seed-demo`; it creates three links and 16 synthetic visits and stops if any demo code already exists. These commands change database records, so use the intended judge account and database.
