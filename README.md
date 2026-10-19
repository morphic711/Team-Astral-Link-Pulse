# LinkPulse: URL Shortener & Analytics Platform

Tech Geeks Hackathon, Round 2 | Team Astral

**Live app:** https://linkpulse-s4uz.onrender.com
**Repo:** https://github.com/morphic711/Team-Astral-Link-Pulse

> Free hosting sleeps when idle, so the first load can take up to a minute. Please wait and refresh once.

## Problem statement

Long campaign URLs are hard to share and manage, teams can't easily see whether anyone clicks them, and a link sometimes has to be stopped without losing its history.

## Solution

LinkPulse creates short links, redirects visitors, records every click, and shows per-link analytics. Admins can disable a link while its click history is kept.

## Features

- Accounts with user and admin roles
- Short links with a generated code or a custom alias, with URL and code validation (the links in the dashboard have a copy option so that user dont have to copy the link manully to share it)
- HTTP 302 redirects
- **Link rules: expiry date, click limit and optional password**, checked in this order: disabled, expired, click limit, password
- Click tracking (time, referrer, device, browser, OS) with hashed visitor IPs and a per-link analytics page
- Admin-only link disable (HTTP 410, analytics kept)
- CSV import (`destination_url` required, `short_code` optional; invalid rows and duplicates are skipped)
- Security: hashed passwords, CSRF protection, user-scoped dashboards

**Planned, not built yet:** campaigns and tags, QR codes, unique visitors and charts, bot-filtered reports, rate limiting, domain blocklist, link-in-bio, device targeting, custom domains, public API.


## Tech stack

Python 3.14, Flask, Jinja2, HTML/CSS, Flask-SQLAlchemy, Flask-WTF, PostgreSQL on Supabase, Gunicorn, Render, Git/GitHub.

## Testing guide for judges

Test logins (user and admin) are in the submission form, not in this public repo. You can also register your own account at `/register`. The test user has three **sample** links (`demo-event`, `demo-launch`, `demo-signup`).

1. Sign in and open the dashboard.
2. Create a short link (try an invalid URL or a duplicate code to see validation).
3. Open the short link in a new tab. You are redirected.
4. Open the link's analytics page. Your click appears.
5. **Rules:** create a link with a click limit of 1, an expiry date in the past, or a password, then open it.
   - Expired or limit reached: unavailable page (HTTP 410).
   - Password: a password form appears; a wrong password is refused, the right one redirects.
6. Import a CSV with a `destination_url` column. Bad rows and duplicates are skipped with a message.
7. Sign in as the admin, disable a link, then open it: you get HTTP 410, and its analytics remain.

## Setup

Requires Python 3.14 and a Supabase Postgres database that already has the `app_users`, `links` and `click_events` tables (see the models in `app.py`).

```
git clone https://github.com/morphic711/Team-Astral-Link-Pulse.git
cd Team-Astral-Link-Pulse
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

On macOS/Linux: `python3 -m venv .venv`, `source .venv/bin/activate`, `pip install -r requirements.txt`.

Copy `.env.example` to `.env` and set `DATABASE_URL` (your Supabase connection string) and `SECRET_KEY` (a private random value). Never commit `.env`.

```
.\.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000/register. Optional commands: `flask --app app seed-admin` (create an admin) and `flask --app app seed-demo` (sample data).

## Deployment

Deployed on Render Free from the `main` branch (`render.yaml`, `Procfile` with Gunicorn). `DATABASE_URL` and `SECRET_KEY` are set in Render's private environment settings.
