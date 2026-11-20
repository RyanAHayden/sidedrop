# B19 Settings: Admin Login row for non-admins

## What I did
- `app.py` Settings tab: a new group `id=sAdmin` after Help (just above Sign Out) with one row,
  `Admin Login` (lock tile), `href=/admin data-push`, which pushes /admin's existing admin password
  prompt (rate-limited by `admin_fails`). Shown only when an admin password exists (`admin_on`),
  the viewer is not already admin, and is not an invite guest (`guests_stay_out` 403s /admin for them).
  Admins keep the Admin Settings group and see no login row.
- Placement: after Help, as its own group, so the "a user has no Admin Settings header" check (F29)
  still holds and a login sits beside Sign Out, where sign-in/out actions live.
- `test_app.py`: the non-admin Settings group list now ends with `sAdmin`; the row's exact markup and
  its place (after Help, before Sign Out) are checked; the admin's Settings has no `Admin Login`;
  an invite guest's page has none. Two older "non-admin sees no `href=/admin`" checks now look for
  the Manage row's `href=/admin data-push>` instead, since the login row also links /admin.

## Tried and failed
- nothing

## Not verified
- How the row looks on a real iPhone (no device screenshot taken in this unattended run); it reuses
  the same `g grp sg` / `row mrow` markup as the Help row, so it should render like it.
