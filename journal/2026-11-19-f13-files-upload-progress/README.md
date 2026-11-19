# F13: Files for Friends uploads with progress

## What I did
- `app.py` `POST /admin/files`: with `json=1` it answers `{"name", "size", "html"}` (the file's row, `FILE_ROW`, the same
  template the page uses), or `{"error"}` with 400 (no file) or 500 (the server can't write `files/`). Without `json=1` it
  behaves as before (the redirect, and the error page), which the `<noscript>` Upload button still uses.
- `FILES_PAGE`: the Upload button is gone; picking files (`#upf` `onchange="upAdd(this)"`) starts one `XMLHttpRequest`
  per file at once. Each file is a row at the top of the list: name, Cydia's progress bar (iFizBox `progress.css`'s
  `.progress-track`/`.progress-fill` geometry, 12 px track, 3 px padding, 4 px fill scaled by `scaleX`, drawn in the
  row's `--sub` grey instead of the console's white, so it also follows dark mode) and `Uploading 45% · 12 of 27 MB`
  (GB for files of 1 GB and up; `Saving 27 MB…` once the bytes are sent and the server is still moving the file). When
  the server answers, its row replaces the upload row (and an older row with the same name goes, since the file was
  replaced). An error turns the row red with the server's message, RETRY (sends the same File again) and CLEAR.
  `upload.onprogress`'s `e.total` includes the multipart overhead, so the bytes shown are scaled to the file's size.
- The queue lives on `window.upQ` (jobs keep their `File`), so the uploads run while the page is popped; when the page is
  pushed again (or redrawn after a Delete, which replaces the layer's page), its script draws a row for every job still
  going. Finished jobs leave the queue: the page's server list has them.
- `test_app.py`: the json=1 answer (row html with DELETE and the csrf, file on disk, no `.part` left), json=1 with no file
  (400 + error), the write-protected `files/` answer in JSON (500 + the message), and the page has the picker/queue and
  no visible Upload button.

## Checked in a browser
`ui.py` (here): runs the app, pushes Manage > Files in headless Chromium (`/usr/bin/chromium`, Playwright), throttles
upload to 1.5 MB/s through CDP `Network.emulateNetworkConditions`, picks a 27 MB and a 6 MB file, then a third while
they upload, pops the page and pushes it again, waits for the end, then write-protects `files/` for an error and Retry.
Output of the run:

```
mid: ['Uploading 49% · 2.9 of 6.0 MB', 'Uploading 10% · 3 of 27 MB']
reopened: ['Uploading 83% · 5.0 of 6.0 MB', 'Uploading 18% · 5 of 27 MB']
done rows: ['Save Data.zip | 6.0 MB | DELETE', 'GMPE01.iso | 27.0 MB | DELETE', 'old notes.txt | 1.2 kB | DELETE', 'readme.txt | 5 Bytes | DELETE']
on disk: [('GMPE01.iso', 27000000), ('Save Data.zip', 6000000), ('old notes.txt', 1234), ('readme.txt', 5)]
error: Couldn't save readme.txt: the server can't write to the data folder's files/ (Permission denied).
retried: b'hello'
```

Screenshots: `1-mid-upload.png` (mid-upload), `2-reopened.png` (after leaving and pushing the page again: the uploads
kept going), `3-done.png`, `4-error.png` (red row with RETRY / CLEAR).

## Tried that failed
- First run's "upload button gone" check counted the DELETE buttons (they're in forms too); fixed to look for "Upload".
- The test first expected `2.9 KB`; Jinja's `filesizeformat` is decimal (`3.0 kB`).

## Not verified
- A several-GB upload: not run (disk and time on a shared machine). The server path is unchanged (Werkzeug spools the
  body to a temp file, then `u.save` copies it to the `.part`, then rename); the client uses the `File` directly and
  shows GB. Through the NAS's reverse proxy a body-size limit could still apply; a 413 shows "Too big for the server."
- iPhone Safari (and the home-screen app): only headless Chromium was driven. Safari suspends background tabs, so an
  upload while Safari itself is in the background may pause or fail (it would show the red row with Retry).
- Leaving the page by a full navigation (not the pushed layer) does cancel the uploads; only the pushed-page flow keeps them.
- The bottom "Reloading Data" bar in the screenshots is the main page's own source refresh in this test setup, not F13.
