# B22 Settings rubber-bands even when it all fits

Removed F29's `#t-settings{min-height:0}`, so Settings keeps the shared `.page{min-height:calc(100% + 1px)}` and bounces like the
other tabs. test_app.py now asserts no `#t-settings{min-height` override and that the shared rule is there.

**Not verified**: the bounce on a real iPhone (done from a control session, no phone at hand); the CSS is the same rule every other tab uses.
