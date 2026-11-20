# B2: Register iPhone showed "Method Not Allowed"

The user's iPhone (2026-11-19, live site): Register iPhone opened a Safari page "Method Not Allowed".

Cause (from the code, not a log): POST /enroll answered the POST with the .mobileconfig as an attachment. Safari's
download manager on recent iOS fetches a download again with GET, and /enroll took POST only, so the refetch got 405.
Registrations worked earlier (5 iPhones are in the account), which fits a newer iOS doing the refetch.

Fix: POST /enroll keeps its checks (signed in, the name, a guest's invite) and answers 303 to a signed GET link,
/enroll/profile/<name>[/g/<tok>/<sid>]?e=..&s=.. (30 minutes), which serves the same signed Profile Service payload.
The link needs no session (the signature is the auth) and works when fetched more than once. GET /enroll redirects
to /.

## Not verified
- Not reproduced from a server log: gunicorn runs without an access log, so the failing request was never seen.
  Turning on `--access-logfile -` would help next time, but query strings must stay out (signed links carry tokens).
- Not tried on a phone yet: the user registers again on the live site after the deploy.
