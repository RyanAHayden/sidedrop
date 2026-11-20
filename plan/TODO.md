# TODO — open tasks, in order

### Next

- [ ] **F19** Arctic-style signing: an explicit App ID with Push and every capability the App Store Connect API accepts (missing ones added to an existing App ID; Push must succeed), apps keep their own bundle IDs with entitlements under the profile's App ID (application-identifier and keychain group narrowed to it, get-task-allow false), watch apps removed, extensions kept and signed under the same App ID. At start, a profile made for another certificate or App ID (or an App ID that just got capabilities) is made again and every app re-signed. Check: test_app.py with the fake ASC (caps list, settings, existing App ID, entitlements), docs/developer-account.md and configuration.md say which capabilities. | files: app.py, test_app.py, docs/developer-account.md, docs/configuration.md
### Parked
