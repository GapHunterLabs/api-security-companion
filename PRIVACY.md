# Privacy Policy: API Security Companion

**Effective date:** 2026-11-24

API Security Companion is a Gap Hunter Labs plugin for IntelliJ Platform IDEs.
This policy is short because the plugin's design makes it short: there
is nothing to disclose beyond what's below.

## What this plugin collects

**Nothing.** API Security Companion does not collect, transmit, or sell
any data: no source code, no file contents, no usage analytics, no
telemetry, no personally identifiable information. The only exception is an
error report that you choose to send (see "Error reports" below).

## What it keeps on your machine

To decide when to show its one-time rating prompt, the plugin keeps two values
in the IDE's own settings on your computer: whether you have answered the
prompt, and a list of up to 500 findings it has already counted. Each entry in
that list is a one-way fingerprint that cannot be turned back into a file path
(since version 2026.4.1; the older list of paths was deleted then). None of
this is ever sent anywhere.

Settings you change for the plugin are saved in the IDE's settings, like any
other IDE setting, and are never sent anywhere.

## Network access

**None.** API Security Companion makes zero network calls during normal
operation. Every check, detection, and analysis it performs runs
entirely in-process, inside your IDE, against the code already open in
your editor. Nothing you write, open, or edit is ever sent anywhere.

The one narrow exception: this plugin includes an optional paid Pro
tier. The IDE's built-in `LicensingFacade` may validate a purchased
license locally against JetBrains' own licensing infrastructure, the
same mechanism every commercial JetBrains-ecosystem plugin uses,
entirely separate from and unrelated to the plugin's actual
detection/analysis logic, which still never leaves your machine.

## Error reports (only if you send them)

API Security Companion registers the IDE's standard JetBrains Marketplace
error reporter. When the IDE attributes an exception or a UI freeze to this
plugin, it can send a report to JetBrains Marketplace, where I can read it:

- Only when you send it from the IDE's error dialog, or when you have turned on
  automatic error reporting in the IDE settings.
- The IDE builds and sends the report, not this plugin. For an exception it
  carries the stack trace and the IDE and plugin versions; for a freeze, thread
  dumps and, when the IDE adds them, a performance snapshot and metrics; plus
  anything you write in the dialog.
- It is handled under JetBrains' privacy policy and the JetBrains Marketplace
  terms. I use these reports only to fix the plugin.

## Third parties

None. API Security Companion has no third-party SDKs, no analytics libraries,
no ad networks, no external dependencies that phone home.

## Changes to this policy

If this ever changes, this file will be updated and the change will be
noted in the plugin's `CHANGELOG.md`.

## Contact

Questions about this policy: **contact@gaphunterlabs.com**
