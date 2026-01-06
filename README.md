# Twitch -> Spotify Queue Flask App

This small Flask app lets Twitch-signed-in users link a Spotify account and add tracks to the user's Spotify playback queue.

Environment variables (use `.env` or your environment):

- `BASE_URL` - Public base URL. Must match OAuth redirect URIs you configure. I suggest using an ngrok server for spotify to work.
- `TWITCH_CLIENT_ID`, `TWITCH_CLIENT_SECRET` - Twitch app credentials from [Twitch Dev Console](https://dev.twitch.tv/console/apps/create)
- `SPOTIFY_CLIENT_ID`, `SPOTIFY_CLIENT_SECRET` - Spotify app credentials

Quick start

1. Install dependencies

```bash
pip install -r requirements.txt
```

2. Create a `.env` with the vars above and set `BASE_URL` to your ngrok URL.

3. Configure OAuth apps:

- Twitch redirect URI: `BASE_URL/callback/twitch`
- Spotify redirect URI: `BASE_URL/callback/spotify`

4. Run

```bash
python app.py
```

- Make sure to also run your tunnel or whatever you are using
```bash
# ngrok template
ngrok http --domain=*****-*****-*****.ngrok-free.app 5000
```


5. Visit `BASE_URL` and sign in with Twitch, then link Spotify and use the form to add a track.


# Images

 Queue
![Queue](/images/queue.png)

Search
![Search](/images/search.png)
