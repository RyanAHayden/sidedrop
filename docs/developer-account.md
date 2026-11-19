# Setting up your Apple Developer account

How to set up a developer account so SideDrop signs apps the way paid signing services do: each app keeps its own
bundle ID (so it replaces the original, not a copy beside it) and gets its own notifications. iOS checks the
entitlements' `application-identifier` against the profile, but never the app's Info.plist bundle ID, and registers
the app for push under the Info.plist one. iFizBox confirmed it on a stock iPhone 15 Pro.

SideDrop needs three things from the account: an App Store Connect API key (`asc.p8`), an Apple Distribution
certificate (`cert.p12` and its password) and an App ID. You make only the API key: SideDrop makes the certificate and
the App ID with it, then registers iPhones and makes the Ad Hoc profile itself.

If you'd rather not give SideDrop a key that can make and revoke certificates, see [Manual setup](#manual-setup)
below: you make the certificate and App ID yourself, and the key only registers iPhones.

## 1. Join the Apple Developer Program

[developer.apple.com/programs/enroll](https://developer.apple.com/programs/enroll), $99 a year. A free Apple ID
can't do this: it has no Ad Hoc profiles, no Push and no API keys.

## 2. Make one App Store Connect API key

[App Store Connect](https://appstoreconnect.apple.com/access/integrations/api) > Users and Access > Integrations >
App Store Connect API > Team Keys > **+**. Any name, role **Admin**, Generate.

- Download the key: that's `AuthKey_<Key ID>.p8`. Apple lets you download it only once.
- Note the **Issuer ID**, shown above the list of keys. The **Key ID** is beside the key and in the file's name.

Why Admin: Apple's [roles table](https://developer.apple.com/help/account/access/roles/) lets the Account Holder and
Admins create and revoke distribution certificates; App Managers only with "Access to Certificates, Identifiers &
Profiles", which a team API key can't be given. An **App Manager** key registers iPhones, makes profiles and App IDs,
but Apple refuses it a certificate (SideDrop then says it needs an Admin key). App Manager is enough for the manual
path.

## 3. Upload it

On SideDrop's setup screen (or later **Settings > Manage > Signing**), tap **Choose API Key** and pick the `.p8`
(loose, or in a `.zip` with a text file that holds the Issuer ID). The Key ID is read from the file's name; check it
and fill in the Issuer ID and the **App ID** you want, such as `com.yourname.sideload`, then **Save**.

SideDrop then:

1. makes the App ID if the account doesn't have it: an explicit one gets **Push Notifications**, **App Groups** and
   **Associated Domains** (a wildcard such as `com.yourname.*` gets none; Apple gives wildcards no Push);
2. makes a private key and a certificate signing request on the server, and has Apple issue an **Apple
   Distribution** certificate for it;
3. saves the two as `cert.p12` in the data folder, with a random password kept in `setup.json` beside it (or the
   `P12_PASSWORD` from `.env`, if you set one).

The certificate lasts a year; ad hoc apps stop opening when it expires. Before then, **Settings > Manage > Make New
Certificate** makes another, a new profile, and signs every app again.

### When the account already has the most certificates

Apple allows only a few Apple Distribution certificates per account. When it refuses another, SideDrop lists the
account's distribution certificates (name, when made, when it expires, and which one SideDrop uses) and asks you to
pick one to revoke. It never revokes one by itself. Revoking a certificate stops every app signed with it from
opening, on every iPhone, wherever it was signed: another signing service, Xcode ad hoc builds, an older SideDrop.
App Store and TestFlight apps aren't affected. Pick one you no longer use, confirm, and SideDrop revokes it and makes
the new one in its place.

## 4. iPhones and the profile

You don't register iPhones or make profiles on developer.apple.com. When a friend taps **Register iPhone**, SideDrop
adds the UDID to the account through the API, makes a new Ad Hoc profile for `BUNDLE_ID` with every enabled iPhone
and your certificate, and re-signs every app.

SideDrop makes the profile again only when an iPhone registers or is turned on or off, or the signing files change.
After changing the App ID's capabilities, make it happen yourself: **Settings > Manage** (needs the admin
password), turn any iPhone off, then on again. A profile holds the capabilities the App ID had when it was made.

Apple allows 100 iPhones per account per membership year; turning one off takes it out of the profile, but its slot
frees up only at renewal.

Check the profile has Push:

```sh
openssl smime -inform der -verify -noverify -in data/adhoc.mobileprovision | grep -A1 aps-environment
```

It should say `production`.

Every app SideDrop signs uses the one App ID, so they share a keychain: an app could see another's saved sign-ins.
Fine among friends' own phones; iFizBox makes one App ID per app instead. A wildcard `BUNDLE_ID` still works (the old
way: apps renamed to `com.yourname.<app>`, no push), and so does an explicit one without Push (bundle IDs kept, no
notifications).

## 5. Switching from a wildcard

Apps signed under a wildcard were renamed (`com.yourname.youtube`); with an explicit App ID they keep their real IDs,
so iOS sees them as different apps. Friends install them again from SideDrop and delete the old copies (their data
doesn't carry over). If the App Store copy of an app is on the phone, delete it first: iOS won't put a signed app
over it.

## Manual setup

For when you don't want SideDrop's API key to make certificates. The key can then be **App Manager** (step 2), and you
make the certificate and the App ID yourself.

### M1. Make an Apple Distribution certificate

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

### M2. Make an App ID with Push

[Identifiers](https://developer.apple.com/account/resources/identifiers/list) > **+** > App IDs > App:

- **Explicit**, an ID of your own such as `com.yourname.sideload`. Not a wildcard (`com.yourname.*`): Apple gives
  wildcards no Push.
- Tick **Push Notifications**, **App Groups** and **Associated Domains**. Many apps ask for the last two, and an app
  that asks for one the App ID lacks just goes without it.
- Continue, Register.

### M3. Upload them

On the setup screen or **Settings > Manage > Signing**, open **Manual setup**, tap **Choose Signing Files** and pick
`cert.p12` and a `password.txt` with its password (or type it in **P12 Password**), alongside the API key and the App
ID as in step 3. SideDrop then uses your certificate and asks Apple to make nothing.

Or put them on the server without an iPhone. In the data folder (owned by UID 568):

```
asc.p8      the API key
cert.p12    from M1
```

and in `.env`:

```
BUNDLE_ID=com.yourname.sideload
P12_PASSWORD=...
ASC_KEY_ID=...
ASC_ISSUER_ID=...
```

Then restart SideDrop (`docker compose up -d`, or `deploy.sh -f`).

## When it doesn't work

- **"making certificates needs an API key with the Admin role"**: the key is App Manager or lower. Make an Admin key
  (step 2), or use the manual setup.
- **"Unable to install … integrity could not be verified"**: the iPhone isn't in the profile. Register it again from
  the site, or check Settings > Manage that it's on.
- **The app installs but won't open**: Developer Mode is off (Settings > Privacy & Security > Developer Mode), or the
  certificate expired or was revoked.
- **No notifications**: the profile has no `aps-environment` (Push wasn't on the App ID when the profile was made:
  step 4), `BUNDLE_ID` is still a wildcard, or the app was never allowed to send notifications.
- **Signing fails after changing `BUNDLE_ID`**: on the manual path the App ID must already exist on
  developer.apple.com, spelled exactly as in `.env`. A new App ID saved on Manage is made if the account lacks it
  and the key may make App IDs; the banner at the top of Manage says when it's still missing.
