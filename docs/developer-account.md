# Setting up your Apple Developer account

How to set up a developer account so SideDrop signs apps the way paid signing services do: each app keeps its own
bundle ID (so it replaces the original, not a copy beside it) and gets its own notifications. iOS checks the
entitlements' `application-identifier` against the profile, but never the app's Info.plist bundle ID, and registers
the app for push under the Info.plist one. Apple delivers a notification to that bundle ID whichever team signed the
app, so the app's own servers reach it as long as the profile has `aps-environment`, plus, for some apps, the app
groups and notification capabilities that only developer.apple.com sets ([Capabilities](#capabilities)). iFizBox
confirmed it on a stock iPhone 15 Pro.

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

1. makes the App ID if the account doesn't have it, and gives an explicit one every capability it lacks from the list
   in [Capabilities](#capabilities) (a wildcard such as `com.yourname.*` gets none; Apple gives wildcards no Push);
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

SideDrop makes the profile again when an iPhone registers or is turned on or off, when the signing files change on
Manage, and when it starts and finds the profile made for another certificate or App ID (you changed `cert.p12`,
`P12_PASSWORD` or `BUNDLE_ID` on the server) or had to add capabilities to the App ID. A profile holds the
capabilities the App ID had when it was made, and any change to the App ID's capabilities or groups on
developer.apple.com marks the existing profile **Invalid**. After changing them yourself, make it again: **Settings >
Manage** (needs the admin password), turn any iPhone off, then on again. That makes a new profile and signs every app
again; apps already on a phone get the new entitlements once installed again from the site.

iFizBox signed by SideDrop carries the new profile inside it, but iFizBox keeps a signing identity it already has:
friends who had iFizBox before import the new profile in iFizBox (Settings › Installation & Signing) to sign with it.

Apple allows 100 iPhones per account per membership year; turning one off takes it out of the profile, but its slot
frees up only at renewal.

Check the profile:

```sh
openssl smime -inform der -verify -noverify -in data/adhoc.mobileprovision \
  | grep -A3 -E 'aps-environment|application-groups|usernotifications'
```

`aps-environment` should say `production`, `com.apple.security.application-groups` should list your groups (not be
empty), and `com.apple.developer.usernotifications.communication` and `.time-sensitive` should be there (see
[Capabilities](#capabilities)).

### How apps are signed

With an explicit App ID, every app keeps its own bundle ID in Info.plist (YouTube stays `com.google.ios.youtube`),
iFizBox included. Only the entitlements carry the App ID: `application-identifier` is `TEAM.<App ID>`, the keychain
groups are narrowed to the app's own (`TEAM.<its bundle ID>`, first) and then `TEAM.<App ID>`, `get-task-allow` is
off, and the rest is what the profile grants. App extensions (share sheets, widgets, notification services) stay,
keep their own IDs and get the same entitlements; watch apps are removed, since no watch is in the profile.

Every app SideDrop signs uses the one App ID, but each keeps its keychain items in its own group (the first one), so
one app clearing its keychain no longer signs the others out ([Keep your apps' data](#keep-your-apps-data)).
iFizBox can make one App ID per app instead. A wildcard `BUNDLE_ID` still works (the old
way: apps renamed to `com.yourname.<app>`, no push), and so does an explicit one without Push (bundle IDs kept, no
notifications).

### Capabilities

SideDrop turns these on for an explicit App ID, when it makes it and at every start (adding only what's missing):
every capability App Store Connect's API accepts for an App ID.

- Push Notifications (it must succeed; the others are skipped with a line in the log if Apple refuses one)
- App Groups, Associated Domains, iCloud (CloudKit), Game Center, HealthKit, HomeKit, SiriKit
- Network Extensions, Personal VPN, Multipath, Hotspot, NFC Tag Reading, Access Wi-Fi Information
- ClassKit, AutoFill Credential Provider, Low-Latency HLS, Sign in with Apple, Wallet, In-App Purchase
- Inter-App Audio, Wireless Accessory Configuration, Data Protection (complete), Maps, Apple Pay

That list is not enough for every app's notifications. The API turns App Groups on but can't make groups or assign
them, so the profile carries an empty `com.apple.security.application-groups`, and it can't turn on communication or
time-sensitive notifications at all. Apps with a notification service extension, such as a modded Discord, then get
no notifications. Add these on developer.apple.com, all together (which one an app needs varies):

1. [Identifiers](https://developer.apple.com/account/resources/identifiers/list) > the filter at the top right >
   **App Groups** > **+**: make a few groups, such as `group.com.yourname.sideload.1` to `.5`. Apps use whatever
   groups the profile gives them.
2. Open the App ID (`BUNDLE_ID`) > **App Groups** > **Configure**, select every group, **Save**.
3. On the same App ID's **Capabilities** tab, tick **Communication Notifications** and **Time Sensitive
   Notifications**, then **Save**.

While you're there you can also tick the other ones the API can't set: App Attest, Fonts, Extended Virtual
Addressing, Increased Memory Limit and Increased Debugging Memory Limit (Capabilities), and WeatherKit (App
Services). Skip Multitasking Camera Access and the HealthKit estimates: Apple grants those only on request, and apps
don't need them. SideDrop leaves capabilities it didn't add alone; an app that asks for one the profile lacks goes
without it.

Then make the profile again ([step 4](#4-iphones-and-the-profile)) and check it. A profile made this way matches
what paid signing services hand out.

### Keep your apps' data

A signed app keeps its settings and sign-ins across every re-sign (a new profile, a new iPhone added, a new
certificate) as long as three things stay the same:

- **The team.** Keychain groups start with the team ID, and iOS refuses an update from another team.
- **The App ID** (`BUNDLE_ID`). Every app's `application-identifier` is `TEAM.<App ID>`; iOS refuses to install an
  app over a copy with another one (`MismatchedApplicationIdentifierEntitlement`).
- **The app's bundle ID.** With an explicit App ID SideDrop always keeps the app's own bundle ID (the same as Keep
  Bundle IDs in iFizBox's signer), so its own keychain group, `TEAM.<its bundle ID>`, doesn't change.

A new App ID or a new team forces deleting the app and installing it again, and deleting it deletes its data. Back up
what the app can export first (RyukGram's settings, for one).

Store apps also ask for their original app groups (`group.com.burbn.instagram`) and keychain groups, which no profile
of yours can give: iOS answers with nothing, and the app forgets imported settings and asks you to sign in again.
SideDrop reads those from the app's own signature and, when the profile lacks them, puts a small fix in the app
(`sidedrop-groupfix.dylib`, the same fix iFizBox's signers use, with `sidedrop-groupfix.plist` beside it): each such
group's folder becomes `Library/AppGroups/<group>/` in the app's own data and its settings a suite of its own, and
keychain calls lose the group they named, so items land in the app's own group. That place is the same on every
re-sign, under any profile, and no other app shares it. The profile's own app groups stay in the entitlements, for
apps (and their notification extensions) that use whatever groups the profile gives.

Apps signed before this fix stored nothing in those groups (iOS gave them no folder), so nothing is lost by the
change. Their keychain items stay in the old shared group (`TEAM.<App ID>`), which is still in every app's
entitlements, so they are still read; new items go to the app's own group. Until an app writes them again, another
app clearing its keychain can still delete those old items, so one more sign-in may be needed after that.

If you change the App ID (or its capabilities) on developer.apple.com, the profile is no longer valid: make it again
([step 4](#4-iphones-and-the-profile)).

## 5. Switching from a wildcard

Apps signed under a wildcard were renamed (`com.yourname.youtube`); with an explicit App ID they keep their real IDs,
so iOS sees them as different apps. Friends install them again from SideDrop and delete the old copies (their data
doesn't carry over). If the App Store copy of an app is on the phone, delete it first: iOS won't put a signed app
over it.

An app whose ID already fitted the wildcard (`com.yourname.app` under `com.yourname.*`) keeps the same ID, but its `application-identifier` changes from `TEAM.com.yourname.app` to `TEAM.<App ID>`. iOS may refuse
to install that over the old copy; if it does, delete the old copy first.

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
- Tick **Push Notifications**, **Communication Notifications** and **Time Sensitive Notifications**. SideDrop adds
  the rest of the API's list itself when the API key may (App Manager can); an app that asks for one the App ID lacks
  just goes without it.
- Continue, Register. Then make app groups and assign them to the App ID, as in [Capabilities](#capabilities).

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
  step 4), `BUNDLE_ID` is still a wildcard, or the app was never allowed to send notifications. If Push is there but
  an app such as Discord still gets nothing, the profile lacks app groups or communication and time-sensitive
  notifications: add them as in [Capabilities](#capabilities), make the profile again and install the app again.
  Testing with Discord: it pushes to the phone only while its desktop and web clients are inactive.
- **Signing fails after changing `BUNDLE_ID`**: on the manual path the App ID must already exist on
  developer.apple.com, spelled exactly as in `.env`. A new App ID saved on Manage is made if the account lacks it
  and the key may make App IDs; the banner at the top of Manage says when it's still missing.
