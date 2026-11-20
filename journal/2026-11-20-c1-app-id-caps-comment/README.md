# C1: APP_ID_CAPS comment

Reworded the comment above `APP_ID_CAPS` in app.py. It used to say the website-only capabilities (communication and
time-sensitive notifications, WeatherKit, App Attest, fonts, memory limits) are "never in the profile". The new text says
the API can't set them (or make and assign app groups), and that once they're ticked on developer.apple.com they're in the
next `regen_profile`, pointing at docs/developer-account.md's Capabilities section. Multitasking camera is now described as
granted by Apple only, which matches the docs. Only the comment changed.

Nothing failed along the way.

**Not verified**: none. This is a comment-only change; the gate covers the rest.
