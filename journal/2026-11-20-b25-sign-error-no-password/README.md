# B25: a failed sign no longer shows the P12 password

## What I did
- `app.py`: new `run_zsign(name, cmd)` and `SignFailed`. `sign_ipa` calls zsign through it. A failure becomes
  `SignFailed("Couldn't sign <app>: zsign exited with <code>: <zsign's last output line>")` (or "took over 600s",
  or "didn't start (<strerror>)"), raised after the except block, so neither the message, a traceback nor the
  error's `__context__` carries subprocess's own error, whose text is the whole argv with `-p P12_PASSWORD`.
  zsign's output is captured (`capture_output=True`) to take that last line from, and printed to the log as
  before; a password zsign itself echoes is replaced by `…` in both. index() (`error = str(e)`), resign_logged, resign_all and resign_bg_loop needed no change: they
  print/show `str(e)`, which is now ours.
- `test_app.py`: a failing zsign (exit 2, timeout, missing binary, and one whose stderr echoes the password) gives
  the expected messages, no `__context__`, and no password in the message, the formatted traceback or the log;
  the Apps page and the log lines of resign_logged, resign_all and resign_bg_loop show "Couldn't sign Demo:
  zsign exited with 2" and no password.

## Tried and failed
- First version used `raise … from None`: the spec review pointed out the original error (with the argv) was
  still kept as `__context__`, which error tools walk. Now raised outside the except block.
- First version stopped zsign's output reaching the log at all (captured, only the last line kept); the review
  flagged it as a change not asked for, so it is printed again, password blanked.

## Not verified
- A real zsign failure on apps.hayde.in: not run from here (the task is the code fix; deploying is the runner's
  publish). The live wording of zsign 1.1.2's last stderr line is assumed to be a plain message line, as in the
  test stub.
