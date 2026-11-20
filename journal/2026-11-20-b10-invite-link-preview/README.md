# B10: invite links show a link preview in chats

## What a crawler got before
I probed both links with a Discordbot user agent, through Flask's test client and following redirects, once with cookies kept and
once without:

| link | no cookies | cookies kept |
|---|---|---|
| /join/<valid> | 302 → / (sign-in page, 57 KB), og tags | 302 → / **signed in as a friend**, full app page (115 KB) |
| /invite/<valid unused> | 302 → / (57 KB) | 302 → / **signed in as a guest** (115 KB) |
| /invite/<used>, expired or revoked | **403** | **403** |
| /join/<rotated or old> | **403** | **403** |

Every page has the base og tags (PAGE in app.py), so the tags weren't missing. What blocked the embed was the status code or the
redirect: Discord and facebookexternalhit (which iMessage's LinkPresentation also sends) show no card for a 4xx. A cookie-keeping
crawler was also signed in and redirected to the full home page, and home() may run resign() before it answers, which can outlast a
crawler's timeout. I can't tell which link the user pasted. Most likely it was a used one-iPhone link or an old /join link (a 403) next
to a valid one. The fix covers every case.

## What I did
- `link_preview()` in app.py: when the User-Agent looks like a preview crawler (PREVIEW_UA: Discordbot, facebookexternalhit/Facebot,
  Twitterbot, WhatsApp (Signal sends this too), Slack, Telegram, LinkedIn, Embedly/Iframely, Skype, generic bot/crawler/spider),
  /join/<tok> and /invite/<tok> answer 200 with a small page (under 4 KB): og:title "You're invited to SideDrop", the description,
  og:image static/og.png (absolute URL), og:url set to the link itself, twitter card tags, and `Cache-Control: no-store`. It runs
  before anything reads the token or the session, so no session cookie is set, nothing signs in and no invite is used. Whether the
  link is valid isn't revealed either: every link gets the same card.
- test_app.py: three crawler UAs × (valid /join, unused /invite, used /invite, bad /join, bad /invite) each get a 200 with
  og:title/og:image/og:url, no Set-Cookie, no password form, and the client still isn't signed in. /static/og.png serves with no
  session, and the invite still reads "Not used" afterwards.

## Tried and dropped
- Answering 200 instead of 403 for refused links to everyone: browsers would lose the error status for no gain. A crawler-only
  branch is smaller and leaves the human flow alone.

## Not verified
- How real Discord, iMessage and WhatsApp render the card. That needs the deployed server and the apps, and an unattended run can't
  publish or paste into them. The UA strings come from what those services are documented or known to send. A crawler with an
  unusual UA still gets the old behaviour (200 with base og tags when the link is valid, 403 when it's not).
- Which of the two links the user originally saw fail (see above). The fix doesn't depend on it.
