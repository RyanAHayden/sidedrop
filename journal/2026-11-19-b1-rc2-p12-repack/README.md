# B1: repack RC2/RC4 cert.p12 files as 3DES

The finding (journal/2026-11-19-f19-arctic-signing): a Keychain export encrypts its certificate bag with
pbeWithSHA1And40BitRC2-CBC. Python's cryptography opens it, so the upload checks pass, but the image's static musl
zsign 1.1.2 can't load OpenSSL's legacy provider and every signing fails ("Can't load p12 or private key file").

## What I did

- `app.py`: `p12_repacked(blob, pw)` looks for the PKCS#12 PBE OIDs zsign can't open (1.2.840.113549.1.12.1.1/2/4/5/6:
  RC4-128/40, 2-key DES, RC2-128/40) in the DER and, when one is there, writes the same key, certificate (with its
  friendly name) and extra certificates again under the same password as 3DES/SHA1, 50000 rounds, SHA1 MAC — what
  `make_certificate` writes. 3DES (.3) and PBES2/AES (cryptography's BestAvailableEncryption, openssl 3's default)
  are left alone, so the file doesn't change on every start.
- `save_p12` writes cert.p12 (repacked when needed, original kept as cert.p12.bak, both 0600). The setup splash's and
  Manage's upload (`take_signing_files`) now go through it.
- `repack_p12` runs first in `heal_signing` (at start), for a cert.p12 saved before this or copied in by hand. It runs
  before heal_signing's early return, so it also works before setup is done when P12_PASSWORD is known.
- A password-less RC2 .p12 is written with no encryption (cryptography refuses an empty PBE password).
- Chose to repack rather than refuse: the user's file is good, only its wrapping isn't, and the .bak keeps it.
- `test_app.py`: builds an RC2-40 p12 from the test key/certificate with `openssl pkcs12 -export -legacy -certpbe
  PBE-SHA1-RC2-40` when openssl is present, else copies `fixtures/rc2-legacy.p12` (made with the same command, its own
  EC key and an "Apple Distribution: Fixture Test" certificate valid to 2126, password `fixture-pw`). Uploads it on
  a fresh setup splash and boots another data folder with it as cert.p12 and runs heal_signing; asserts the saved file
  has the 3DES OID and no RC2 OID, the .bak is the original, key and certificate are equal, a second start doesn't
  rewrite it, and (with openssl) that `openssl pkcs12` without `-legacy` opens the new file and not the .bak.

## Tried and failed

- Making the RC2 file with `subprocess.run` in the test hit zsign's stub (`fake_run` asserts `--rm_watch`): the test
  calls openssl through `Popen` instead.

## Checks

- Gate passes with openssl 3.6.5 (the openssl branch). The fixture branch was checked by hand: the fixture passes
  `cert_problems`, repacks to 3DES, and the repacked file isn't repacked again.

## Not verified

- The real zsign 1.1.2 binary signing with a file repacked by this code: not on this machine in the test. F19's
  journal repacked the real Keychain export the same way (same algorithm and settings) and zsign signed with it;
  here openssl 3 without the legacy provider stands in for zsign.
- The password-less RC2 case (written unencrypted): not tested, no such file seen in practice.
