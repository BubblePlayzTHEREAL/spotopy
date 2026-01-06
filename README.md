# Twitch -> Spotify Queue Flask App

This small Flask app lets Twitch-signed-in users link a Spotify account and add tracks to the user's Spotify playback queue.

Environment variables (use `.env` or your environment):

- `SECRET_KEY` - Flask session secret
- `BASE_URL` - Public base URL (default `http://localhost:5000`). Must match OAuth redirect URIs you configure.
- `TWITCH_CLIENT_ID`, `TWITCH_CLIENT_SECRET` - Twitch app credentials
- `SPOTIFY_CLIENT_ID`, `SPOTIFY_CLIENT_SECRET` - Spotify app credentials

Quick start

1. Install dependencies

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

2. Create a `.env` with the vars above and set `BASE_URL` to `http://localhost:5000` for local testing.

3. Configure OAuth apps:
- Twitch redirect URI: `BASE_URL/callback/twitch`
- Spotify redirect URI: `BASE_URL/callback/spotify`

4. Run

```bash
# Development
python app.py

# Production (recommended): use `waitress` WSGI server
USE_PROXY_FIX=1 USE_WAITRESS=1 PORT=5000 python -c "from waitress import serve; import app; serve(app.app, host='0.0.0.0', port=5000)"
```

5. Visit `BASE_URL` and sign in with Twitch, then link Spotify and use the form to add a track.

Notes

- This demo stores tokens in memory (`TOKENS` dict). For production use a persistent store.
- Add CSRF/state validation and secure session store for production.
 - The app sets several security headers and `SESSION_COOKIE_SECURE` when `BASE_URL` uses https.
 - Recommended production steps:
	 - Use a persistent datastore for tokens (Redis, database).
	 - Run behind a TLS-terminating reverse proxy (nginx) and set `USE_PROXY_FIX=1`.
	 - Use a real secret in `SECRET_KEY` and do not commit `.env`.
	 - Consider adding Twitch follower/subscriber checks to gate who can add tracks.
