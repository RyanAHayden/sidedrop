# TODO — open tasks, in order

### Next
- [ ] **F3** User first-launch splash: the first time a user taps an app to install, show a one-time splash walking through turning off/setting up Stolen Device Protection and enabling Developer Mode (static/sdp*.jpg and dev*.jpg exist and the page already explains Developer Mode; reuse that), then continue the install. Remember it was shown per device. Check: test_app.py sees the splash on first install tap only. | files: app.py, test_app.py, static/**
- [ ] **F5** Bring over iFizBox's UI improvements: compare sidedrop's page to the current iFizBox web app (~/repos/iFizBox web/app) and port the look/feel improvements made since sidedrop copied it (nav and tab bars, lists, pressed states, alerts, settings rows and switches). Write the list of what was ported in the commit. Check: test_app.py still passes; screenshots before/after in the journal. | files: app.py, static/**
