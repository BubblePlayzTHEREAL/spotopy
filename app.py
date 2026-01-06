import os
import time
import base64
from urllib.parse import urlencode

import gevent.monkey

gevent.monkey.patch_all()

import requests
import gevent
from flask import Flask, session, redirect, request, url_for, render_template, jsonify
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_socketio import SocketIO

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

# SocketIO for realtime updates
socketio = SocketIO(app, cors_allowed_origins="*")


@socketio.on("connect")
def handle_connect():
    print("Client connected")
    # send current queue to all clients (including new one)
    fetch_spotify_queue()


@socketio.on("disconnect")
def handle_disconnect():
    print("Client disconnected")


# Production-related defaults
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("BASE_URL", "").startswith("https")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

# If running behind a reverse proxy (nginx, cloud), enable ProxyFix by setting USE_PROXY_FIX=1
if os.environ.get("USE_PROXY_FIX") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)


@app.after_request
def set_security_headers(response):
    response.headers.setdefault(
        "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer-when-downgrade")
    response.headers.setdefault("Permissions-Policy", "geolocation=()")
    return response


# Configuration - set these env vars
SPOTIFY_CLIENT_ID = os.environ.get("SPOTIFY_CLIENT_ID")
SPOTIFY_CLIENT_SECRET = os.environ.get("SPOTIFY_CLIENT_SECRET")
TWITCH_CLIENT_ID = os.environ.get("TWITCH_CLIENT_ID")
TWITCH_CLIENT_SECRET = os.environ.get("TWITCH_CLIENT_SECRET")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")

# In-memory store mapping twitch_user_id -> spotify token info
TOKENS = {}

# The current streamer's twitch id (set when streamer claims)
STREAMER_ID = None

# In-memory record of queued tracks (this app's log, not Spotify's queue)
QUEUE = []

# In-memory store for current Spotify queue
SPOTIFY_QUEUE = []

# Rate limiting: per-requester last request timestamp (in-memory)
LAST_REQUESTS = {}
RATE_LIMIT_SECONDS = int(os.environ.get("RATE_LIMIT_SECONDS", "240"))

FORCED_STREAMER = os.environ.get("FORCE_STREAMER", "").strip().lower()

# Scopes for Spotify
SPOTIFY_SCOPE = (
    "user-modify-playback-state user-read-playback-state user-read-currently-playing"
)


def fetch_spotify_queue():
    global SPOTIFY_QUEUE
    print("\n==========================================================")
    print(f"Fetching queue for streamer {STREAMER_ID}")
    if not STREAMER_ID:
        print("No streamer set")
        print("==========================================================")
        SPOTIFY_QUEUE = []
        return
    info = ensure_valid_spotify_token(STREAMER_ID)
    if not info:
        print("No valid token for streamer")
        SPOTIFY_QUEUE = []
        return
    access_token = info["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get("https://api.spotify.com/v1/me/player/queue", headers=headers)
    if not r.ok:
        print(f"Failed to fetch queue: {r.status_code} {r.text}")
        SPOTIFY_QUEUE = []
        return
    js = r.json()
    queue = js.get("queue", [])
    print(f"Fetched {len(queue)} tracks from Spotify")
    SPOTIFY_QUEUE = queue
    # merge with local QUEUE for added_by
    merged = []
    for item in queue:
        uri = item.get("uri")
        added_by = None
        for e in QUEUE:
            if e.get("track_uri") == uri:
                added_by = e.get("added_by")
                break
        merged.append(
            {
                "track": {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "artists": [a.get("name") for a in item.get("artists", [])],
                    "uri": uri,
                },
                "added_by": added_by,
            }
        )
    print(f"Merged queue with {len(merged)} items")
    # add any local songs not yet in Spotify queue
    existing_uris = {item["track"]["uri"] for item in merged}
    for e in QUEUE:
        if e["track_uri"] not in existing_uris:
            merged.append(
                {
                    "track": {
                        "id": e["track"]["id"] if e["track"] else None,
                        "name": e["track"]["name"] if e["track"] else e["track_uri"],
                        "artists": e["track"]["artists"] if e["track"] else [],
                        "uri": e["track_uri"],
                    },
                    "added_by": e["added_by"],
                }
            )
    print(f"Final merged queue with {len(merged)} items")
    # emit
    print(f"Emitting queue_updated with {len(merged)} items")
    try:
        socketio.emit("queue_updated", {"queue": merged})
    except Exception:
        app.logger.exception("Failed to emit queue_updated")
    print("==========================================================")


def run_fetch_loop():
    fetch_spotify_queue()
    socketio.start_background_task(run_fetch_loop_with_delay)


def run_fetch_loop_with_delay():
    socketio.sleep(60)
    run_fetch_loop()


# Start the fetch loop
run_fetch_loop()


# Start the fetch loop
run_fetch_loop()


# Twitch authorization URL
def twitch_auth_url():
    params = {
        "client_id": TWITCH_CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/callback/twitch",
        "response_type": "code",
        "scope": "user:read:email",
    }
    return f"https://id.twitch.tv/oauth2/authorize?{urlencode(params)}"


# Spotify authorization URL
def spotify_auth_url():
    params = {
        "client_id": SPOTIFY_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": f"{BASE_URL}/callback/spotify",
        "scope": SPOTIFY_SCOPE,
        "show_dialog": "true",
    }
    return f"https://accounts.spotify.com/authorize?{urlencode(params)}"


@app.route("/")
def index():
    twitch_user = session.get("twitch_user")
    # Only consider the streamer's Spotify link state. Other users should
    # not be able to link or use their tokens.
    spotify_linked = False
    if twitch_user:
        spotify_linked = (
            STREAMER_ID is not None
            and twitch_user.get("id") == STREAMER_ID
            and STREAMER_ID in TOKENS
        )
    return render_template(
        "index.html",
        twitch_user=twitch_user,
        spotify_linked=spotify_linked,
        spotify_auth_url=spotify_auth_url(),
        twitch_auth_url=twitch_auth_url(),
        streamer_id=STREAMER_ID,
    )


@app.route("/login/twitch")
def login_twitch():
    return redirect(twitch_auth_url())


@app.route("/callback/twitch")
def callback_twitch():
    # Basic checks
    if not TWITCH_CLIENT_ID or not TWITCH_CLIENT_SECRET:
        return (
            "Twitch client ID/secret not configured (set TWITCH_CLIENT_ID and TWITCH_CLIENT_SECRET).",
            500,
        )
    code = request.args.get("code")
    if not code:
        return "Missing code", 400
    token_url = "https://id.twitch.tv/oauth2/token"
    redirect_uri = f"{BASE_URL}/callback/twitch"
    # Log the redirect URI being used for exchange to help catch mismatches
    app.logger.debug("Twitch callback: using redirect_uri=%s", redirect_uri)
    data = {
        "client_id": TWITCH_CLIENT_ID,
        "client_secret": TWITCH_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    r = requests.post(token_url, data=data)
    if not r.ok:
        # log response body for debugging
        app.logger.error(
            "Twitch token exchange failed (status=%s): %s", r.status_code, r.text
        )
        return (
            f"Twitch token exchange failed (status={r.status_code}): {r.text}",
            400,
        )
    token_info = r.json()
    access_token = token_info.get("access_token")
    # Fetch user info
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Client-Id": TWITCH_CLIENT_ID,
    }
    ru = requests.get("https://api.twitch.tv/helix/users", headers=headers)
    if not ru.ok:
        app.logger.error(
            "Twitch user fetch failed (status=%s): %s", ru.status_code, ru.text
        )
        return (
            f"Twitch user fetch failed (status={ru.status_code}): {ru.text}",
            400,
        )
    data = ru.json().get("data", [])
    if not data:
        return "No Twitch user returned", 400
    user = data[0]
    twitch_id = user.get("id")
    twitch_display = user.get("display_name")
    # Save minimal user in session
    session["twitch_user"] = {"id": twitch_id, "display_name": twitch_display}
    return redirect(url_for("index"))


@app.route("/login/spotify")
def login_spotify():
    # Only the streamer may link a Spotify account
    twitch_user = session.get("twitch_user")
    if not twitch_user:
        return redirect(url_for("index"))
    if not STREAMER_ID or twitch_user.get("id") != STREAMER_ID:
        return "Only the streamer can link Spotify.", 403
    return redirect(spotify_auth_url())


def exchange_spotify_code(code):
    token_url = "https://accounts.spotify.com/api/token"
    auth = base64.b64encode(
        f"{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}".encode()
    ).decode()
    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"{BASE_URL}/callback/spotify",
    }
    r = requests.post(token_url, data=data, headers=headers)
    if not r.ok:
        return None, r.text
    info = r.json()
    # add expiry time for convenience
    info["expires_at"] = int(time.time()) + info.get("expires_in", 3600)
    return info, None


def refresh_spotify_token(info):
    if not info or "refresh_token" not in info:
        return None
    token_url = "https://accounts.spotify.com/api/token"
    auth = base64.b64encode(
        f"{SPOTIFY_CLIENT_ID}:{SPOTIFY_CLIENT_SECRET}".encode()
    ).decode()
    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {"grant_type": "refresh_token", "refresh_token": info["refresh_token"]}
    r = requests.post(token_url, data=data, headers=headers)
    if not r.ok:
        return None
    new = r.json()
    info["access_token"] = new["access_token"]
    info["expires_in"] = new.get("expires_in", 3600)
    info["expires_at"] = int(time.time()) + info.get("expires_in", 3600)
    if "refresh_token" in new:
        info["refresh_token"] = new["refresh_token"]
    return info


@app.route("/callback/spotify")
def callback_spotify():
    code = request.args.get("code")
    if not code:
        return "Missing code", 400
    # Only the streamer may complete the Spotify link flow
    if "twitch_user" not in session:
        return "You must sign in with Twitch first.", 400
    twitch_id = session["twitch_user"]["id"]
    if not STREAMER_ID or twitch_id != STREAMER_ID:
        return "Only the streamer can link Spotify.", 403
    info, err = exchange_spotify_code(code)
    if err:
        return f"Spotify token exchange failed: {err}", 400
    TOKENS[twitch_id] = info
    # update the queue display since Spotify is linked
    fetch_spotify_queue()
    return redirect(url_for("index"))


def ensure_valid_spotify_token(twitch_id):
    info = TOKENS.get(twitch_id)
    if not info:
        return None
    if info.get("expires_at", 0) - 60 <= int(time.time()):
        updated = refresh_spotify_token(info)
        if not updated:
            TOKENS.pop(twitch_id, None)
            return None
        TOKENS[twitch_id] = updated
        return updated
    return info


@app.route("/set_streamer", methods=["POST"])
def set_streamer():
    """Set the currently-signed-in Twitch user as the streamer.
    If no streamer is set, any signed-in user may claim streamer.
    If a streamer is already set, only the current streamer may re-assert.
    """
    global STREAMER_ID
    twitch_user = session.get("twitch_user")
    if not twitch_user:
        return jsonify({"error": "not_signed_in"}), 401
    if FORCED_STREAMER != "":
        if twitch_user.get("display_name", "").lower() != FORCED_STREAMER:
            return jsonify({"error": "forbidden"}), 403
    tid = twitch_user["id"]
    # If a streamer is already set and it's not the requester, forbid claiming
    if STREAMER_ID and STREAMER_ID != tid:
        return jsonify(
            {"error": "streamer_already_set", "streamer_id": STREAMER_ID}
        ), 403
    STREAMER_ID = tid
    # prune any other stored tokens so only the streamer's token (if present)
    # is used by the app. Preserve the streamer's token if it already exists.
    streamer_token = TOKENS.get(STREAMER_ID)
    TOKENS.clear()
    if streamer_token:
        TOKENS[STREAMER_ID] = streamer_token

    # notify clients that streamer changed
    print(f"Emitting streamer_changed with streamer_id {STREAMER_ID}")
    try:
        socketio.emit("streamer_changed", {"streamer_id": STREAMER_ID})
    except Exception:
        app.logger.exception("Failed to emit streamer_changed")

    return redirect(url_for("index"))


@app.route("/unset_streamer", methods=["POST"])
def unset_streamer():
    global STREAMER_ID
    twitch_user = session.get("twitch_user")
    if not twitch_user:
        return jsonify({"error": "not_signed_in"}), 401
    if STREAMER_ID != twitch_user["id"]:
        return jsonify({"error": "forbidden"}), 403
    STREAMER_ID = None
    print("Emitting streamer_changed with streamer_id None")
    try:
        socketio.emit("streamer_changed", {"streamer_id": None})
    except Exception:
        app.logger.exception("Failed to emit streamer_changed")
    return redirect(url_for("index"))


@app.route("/search")
def search_tracks():
    """Search Spotify tracks using the streamer's linked Spotify account.
    Query param: `q` (required)
    """
    q = request.args.get("q")
    if not q:
        return jsonify({"error": "missing_query"}), 400
    if not STREAMER_ID:
        return jsonify({"error": "no_streamer_set"}), 400
    info = ensure_valid_spotify_token(STREAMER_ID)
    if not info:
        return jsonify({"error": "streamer_spotify_unavailable"}), 503
    access_token = info.get("access_token")
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"q": q, "type": "track", "limit": 10}
    r = requests.get(
        "https://api.spotify.com/v1/search", headers=headers, params=params
    )
    if not r.ok:
        return jsonify(
            {"error": "spotify_search_failed", "details": r.text}
        ), r.status_code
    js = r.json()
    tracks = []
    for t in js.get("tracks", {}).get("items", []):
        tracks.append(
            {
                "id": t.get("id"),
                "name": t.get("name"),
                "artists": [a.get("name") for a in t.get("artists", [])],
                "uri": t.get("uri"),
                "preview_url": t.get("preview_url"),
            }
        )
    return jsonify({"tracks": tracks})


def _extract_track_id(uri_or_url: str):
    if not uri_or_url:
        return None
    # spotify URI: spotify:track:{id}
    if uri_or_url.startswith("spotify:track:"):
        return uri_or_url.split(":")[-1]
    # open.spotify.com URL
    try:
        if "open.spotify.com/track/" in uri_or_url:
            parts = uri_or_url.split("track/")
            tail = parts[1]
            return tail.split("?")[0].split("/")[0]
    except Exception:
        return None
    # otherwise, maybe the caller provided id
    return uri_or_url


def _fetch_track_meta(track_id: str, access_token: str):
    if not track_id:
        return None
    headers = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(f"https://api.spotify.com/v1/tracks/{track_id}", headers=headers)
    if not r.ok:
        return None
    t = r.json()
    return {
        "id": t.get("id"),
        "name": t.get("name"),
        "artists": [a.get("name") for a in t.get("artists", [])],
        "uri": t.get("uri"),
    }


@app.route("/add", methods=["POST"])
def add_to_queue():
    # Any signed-in Twitch user can request to add a track, but the request
    # will be performed using the streamer's linked Spotify account.
    twitch_user = session.get("twitch_user")
    if not twitch_user:
        return jsonify({"error": "not_signed_in"}), 401
    # enforce per-user rate limit
    requester_id = twitch_user["id"]
    last = LAST_REQUESTS.get(requester_id)
    if last is not None:
        elapsed = time.time() - last
        if elapsed < RATE_LIMIT_SECONDS:
            retry_after = int(RATE_LIMIT_SECONDS - elapsed)
            resp = jsonify({"error": "rate_limited", "retry_after": retry_after})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry_after)
            return resp

    if not STREAMER_ID:
        return jsonify({"error": "no_streamer_set"}), 400
    info = ensure_valid_spotify_token(STREAMER_ID)
    if not info:
        return jsonify({"error": "streamer_spotify_unavailable"}), 503

    print("\n==========================================================")
    print(f"Add to queue requested by Twitch user {requester_id}")

    track_uri = request.form.get("track_uri") or (
        request.json and request.json.get("track_uri")
    )
    device_id = request.form.get("device_id") or (
        request.json and request.json.get("device_id")
    )
    print("Got form data")
    if not track_uri:
        return jsonify({"error": "missing_track_uri"}), 400
    access_token = info.get("access_token")
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"uri": track_uri}
    if device_id:
        params["device_id"] = device_id
    q = urlencode(params)
    url = f"https://api.spotify.com/v1/me/player/queue?{q}"
    print("Set up request")
    r = requests.post(url, headers=headers)
    print("Sent request")
    if r.status_code in (204, 202, 200):
        # record who added what to our local queue log
        try:
            track_id = _extract_track_id(track_uri)
            meta = _fetch_track_meta(track_id or "", access_token)
        except Exception:
            meta = None
        entry = {
            "added_at": int(time.time()),
            "added_by": {
                "id": requester_id,
                "display_name": twitch_user.get("display_name"),
            },
            "track_uri": track_uri,
        }
        print("Prepared queue entry")
        if meta:
            entry.update({"track": meta})
        QUEUE.append(entry)
        print("Added entry to local QUEUE")
        LAST_REQUESTS[requester_id] = time.time()
        # update the queue display immediately
        print("Fetching updated queue after add")
        print("==========================================================")
        fetch_spotify_queue()
        return jsonify({"ok": True})
    else:
        print(f"Status code {r.status_code} not in specified list")
        print("==========================================================")
        return jsonify({"error": "spotify_failed", "details": r.text}), r.status_code


@app.route("/queue")
def view_queue():
    """Return the app's record of queued tracks (most recent last)."""
    # Return a shallow copy to avoid callers mutating internal structure
    return jsonify({"queue": QUEUE})


@app.route("/spotify_queue")
def spotify_queue():
    merged = []
    for item in SPOTIFY_QUEUE:
        uri = item.get("uri")
        added_by = None
        for e in QUEUE:
            if e.get("track_uri") == uri:
                added_by = e.get("added_by")
                break
        merged.append(
            {
                "track": {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "artists": [a.get("name") for a in item.get("artists", [])],
                    "uri": uri,
                },
                "added_by": added_by,
            }
        )
    return jsonify({"queue": merged})


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    port = int(os.environ.get("PORT", "5000"))
    # Use socketio.run which works with eventlet/gevent
    socketio.run(app, host="0.0.0.0", port=port, debug=debug)
