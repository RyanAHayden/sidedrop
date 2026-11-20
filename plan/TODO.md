# TODO — open tasks, in order

### Next

- [ ] **B1** A cert.p12 whose bags use RC2-40 (macOS Keychain exports, openssl without -legacy on old builds) passes SideDrop's checks (Python cryptography opens it) but the image's static musl zsign 1.1.2 can't load OpenSSL's legacy provider and every signing fails with 'Can't load p12 or private key file'. Fix: when a cert.p12 is saved (upload on setup/Manage) and at start (heal_signing), re-serialize it with the same key, certificate and password as 3DES/SHA1 PKCS#12 like make_certificate does (keep a .bak), or refuse it with a clear message. Check: test_app.py builds an RC2-encrypted p12 (cryptography can't write RC2: make one with openssl pkcs12 -export -legacy -certpbe PBE-SHA1-RC2-40 in the test only if openssl is present, else a fixture) and asserts the saved file is 3DES; journal/2026-11-19-f19-arctic-signing has the finding. | files: app.py, test_app.py
### Parked
