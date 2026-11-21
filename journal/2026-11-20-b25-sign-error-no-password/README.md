# B25: a failed sign no longer shows the P12 password

## What I did
- `app.py`: new `run_zsign(name, cmd)` and `SignFailed`. `sign_ipa` calls zsign through it. A failure becomes
  `SignFailed("Couldn't sign <app>: zsign exited with <code>: <zsign's last output line>")` (or "took over 600s",
  or "didn't start (<strerror>)"), raised `from None`, so neither the message nor a traceback carries
  subprocess's own error, whose text is the whole argv with `-p P12_PASSWORD`. zsign's output is now captured
  (`capture_output=True`) to take that last line from; if zsign itself echoed the password in it, it is
  replaced by `…`. index() (`error = str(e)`), resign_logged, resign_all and resign_bg_loop needed no change: they
  print/show `str(e)`, which is now ours.
- `test_app.py`: a failing zsign (exit 2, timeout, missing binary, and one whose stderr echoes the password) gives
  the expected messages and no password in the message or the formatted traceback; the Apps page and
  resign_logged's log line show "Couldn't sign Demo: zsign exited with 2" and no password.

## Tried and failed
- nothing

## Not verified
- A real zsign failure on apps.hayde.in: not run from here (the task is the code fix; deploying is the runner's
  publish). The live wording of zsign 1.1.2's last stderr line is assumed to be a plain message line, as in the
  test stub.
