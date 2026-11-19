# Setting up your Apple Developer account

How to set up a developer account so sidedrop signs apps the way paid signing services do: each app keeps its own
bundle ID (so it replaces the original, not a copy beside it) and gets its own notifications. iOS checks the
entitlements' `application-identifier` against the profile, but never the app's Info.plist bundle ID, and registers
the app for push under the Info.plist one. iFizBox confirmed it on a stock iPhone 15 Pro.

sidedrop needs three things from the account: an App Store Connect API key (`asc.p8`), an Apple Distribution
certificate (`cert.p12` and its password) and an App ID. It registers iPhones and makes the Ad Hoc profile itself.

## 1. Join the Apple Developer Program

[developer.apple.com/programs/enroll](https://developer.apple.com/programs/enroll), $99 a year. A free Apple ID
can't do this: it has no Ad Hoc profiles, no Push and no API keys.

## 2. Make an Apple Distribution certificate

First a certificate signing request (CSR), which makes the private key on your computer.

**On a Mac:** Keychain Access > Keychain Access menu > Certificate Assistant > Request a Certificate From a Certificate
Authority. Your email and name, **Saved to disk**, Continue.

**Anywhere else (Linux, the NAS):**

```sh
openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out request.csr -subj "/emailAddress=you@example.com/CN=Your Name/C=US"
```

Then on [developer.apple.com/account/resources/certificates](https://developer.apple.com/account/resources/certificates/list):
**+** > **Apple Distribution** > upload the CSR > Download (`distribution.cer`).

Turn it into `cert.p12`:

- **Mac:** double-click `distribution.cer`, then in Keychain Access > My Certificates, right-click
  "Apple Distribution: Your Name" > Export > `.p12`, with a password.
- **OpenSSL:**

  ```sh
  openssl x509 -inform der -in distribution.cer -out cert.pem
  openssl pkcs12 -export -legacy -inkey key.pem -in cert.pem -out cert.p12
  ```

  `-legacy` uses the older encryption that every iOS version opens, which matters because iFizBox carries this
  `.p12` onto friends' phones (OpenSSL 1.1 has no `-legacy` flag and needs none).

The password goes in `.env` as `P12_PASSWORD`. The certificate lasts a year; ad hoc apps stop opening when it expires.

## 3. Make an App Store Connect API key

[App Store Connect](https://appstoreconnect.apple.com/access/integrations/api) > Users and Access > Integrations >
App Store Connect API > Team Keys > **+**. Any name, role **Admin** or **App Manager**, Generate.

- Download the key: that's `asc.p8`. Apple lets you download it only once.
- The **Key ID** (beside the key) goes in `.env` as `ASC_KEY_ID`, the **Issuer ID** (above the list) as
  `ASC_ISSUER_ID`.

## 4. Make an App ID with Push

[Identifiers](https://developer.apple.com/account/resources/identifiers/list) > **+** > App IDs > App:

- **Explicit**, an ID of your own such as `com.yourname.sideload`. Not a wildcard (`com.yourname.*`): Apple gives
  wildcards no Push.
- Tick **Push Notifications**, **App Groups** and **Associated Domains**. Many apps ask for the last two, and an app
  that asks for one the App ID lacks just goes without it.
- Continue, Register.

This goes in `.env` as `BUNDLE_ID`. Every app sidedrop signs uses this one App ID, so they share a keychain: an app
could see another's saved sign-ins. Fine among friends' own phones; iFizBox makes one App ID per app instead.

A wildcard `BUNDLE_ID` still works (the old way: apps renamed to `com.yourname.<app>`, no push), and so does an
explicit one without Push (bundle IDs kept, no notifications).

If you add a capability to the App ID later, sidedrop has to make the profile again (step 6): a profile holds the
capabilities the App ID had when it was made.

## 5. Put it on the server

In the data folder (owned by UID 568):

```
asc.p8      from step 3
cert.p12    from step 2
```

and in `.env`:

```
BUNDLE_ID=com.yourname.sideload
P12_PASSWORD=...
ASC_KEY_ID=...
ASC_ISSUER_ID=...
```

Then restart sidedrop (`docker compose up -d`, or `deploy.sh -f`).

## 6. iPhones and the profile

You don't register iPhones or make profiles on developer.apple.com. When a friend taps **Register iPhone**, sidedrop
adds the UDID to the account through the API, makes a new Ad Hoc profile for `BUNDLE_ID` with every enabled iPhone
and your certificate, and re-signs every app.

sidedrop makes the profile again only when an iPhone registers or is turned on or off. After changing `BUNDLE_ID` or
the App ID's capabilities, make it happen yourself: **Settings > Manage** (needs `ADMIN_PASSWORD`), turn any iPhone
off, then on again.

Apple allows 100 iPhones per account per membership year; turning one off takes it out of the profile, but its slot
frees up only at renewal.

Check the profile has Push:

```sh
openssl smime -inform der -verify -noverify -in data/adhoc.mobileprovision | grep -A1 aps-environment
```

It should say `production`.

## 7. Switching from a wildcard

Apps signed under a wildcard were renamed (`com.yourname.youtube`); with an explicit App ID they keep their real IDs,
so iOS sees them as different apps. Friends install them again from sidedrop and delete the old copies (their data
doesn't carry over). If the App Store copy of an app is on the phone, delete it first: iOS won't put a signed app
over it.

## When it doesn't work

- **"Unable to install … integrity could not be verified"**: the iPhone isn't in the profile. Register it again from
  the site, or check Settings > Manage that it's on.
- **The app installs but won't open**: Developer Mode is off (Settings > Privacy & Security > Developer Mode), or the
  certificate expired or was revoked.
- **No notifications**: the profile has no `aps-environment` (Push wasn't on the App ID when the profile was made:
  step 6), `BUNDLE_ID` is still a wildcard, or the app was never allowed to send notifications.
- **Signing fails after changing `BUNDLE_ID`**: the App ID must already exist on developer.apple.com, spelled exactly
  as in `.env`.
