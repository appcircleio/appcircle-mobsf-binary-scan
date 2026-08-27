# Appcircle _MobSF Binary Scan_ component

Runs full MobSF static analysis on the compiled artifact: manifest and permissions, certificate
and signing checks, hardcoded secrets, binary protections, network security config, tracker
detection and the scored AppSec report. Scans an **APK, AAB or IPA**.

Source code analysis is a separate step, MobSF Source Code Scan, which wraps `mobsfscan`.

MobSF is GPL-3.0-only, so it is never shipped with Appcircle and this step never downloads it.
The runner is provisioned with MobSF during setup, and the step only locates that installation
and drives it through `mobsf-control.sh`. **Docker is not required.** A runner without MobSF
fails the step with the provisioning script named, since binary analysis has no CLI equivalent
to fall back to.

Run it after **Android Build** or **Xcodebuild for Devices**, and put Export Build Artifacts
after it.

## Required Input Variables

None. On a workflow that builds first, the step finds the artifact on its own.

## Optional Input Variables

- `AC_MOBSF_ARTIFACT_PATH`: Artifact Path. The APK, AAB or IPA, or the folder holding it. When
  empty the step tries `AC_APK_PATH`, then `AC_AAB_PATH`, then the `.ipa` under `AC_EXPORT_DIR`
  and `AC_OUTPUT_DIR`. iOS exposes no IPA path variable, which is why a folder is accepted.
- `AC_MOBSF_FAIL_ON`: Fail Build On. `critical` (default), `normal`, `low` or `none`. The
  pipeline breaks on a finding at the selected level **or worse**, so `low` is the strictest
  setting and `critical` the loosest. `none` only reports. The levels map onto MobSF's own
  grades: `critical` is `high`, `normal` is `warning`, `low` is `info`. A `secure` entry is a
  passed check and a `hotspot` needs a human, so neither breaks the pipeline.
- `AC_MOBSF_MIN_SCORE`: Minimum Security Score. Breaks the pipeline when MobSF's score out of
  100 falls below this. Empty (default) disables the check. See [The two gates](#the-two-gates).
- `AC_MOBSF_SCAN_TIMEOUT`: Scan Timeout. Seconds for the scan, default `1800`. MobSF's own
  decompile and SAST timeouts are 1000 seconds each, so keep this above their sum.
- `AC_MOBSF_SAVE_REPORT`: Save Report. Copies the report into the artifacts folder when `true`
  (default).

## The two gates

Two independent gates decide the build, and **both are evaluated on every scan**:

| Gate | Input | Reads |
| --- | --- | --- |
| Level gate | `AC_MOBSF_FAIL_ON` (Fail Build On) | the findings |
| Score gate | `AC_MOBSF_MIN_SCORE` (Minimum Security Score) | the MobSF score out of 100 |

They are not chained, so neither one gates the other:

- Either gate on its own breaks the pipeline. The build fails as soon as one of them is breached,
  whatever the other says.
- `Fail Build On = none` disables the level gate only. The score gate stays in force, so a score
  below the minimum still breaks the build.
- A score comfortably above the minimum does not excuse a finding at or above the selected level,
  and a clean level gate does not excuse a low score.
- Leaving Minimum Security Score empty disables the score gate, and the level gate decides alone.

Whichever gate breaks the build, the report is published first, so the findings stay downloadable
on the failing path.

## Output Variables

- `AC_MOBSF_SCANNED_ARTIFACT`: The artifact that was scanned.
- `AC_MOBSF_SECURITY_SCORE`: The score out of 100.
- `AC_MOBSF_FINDING_COUNT`, `AC_MOBSF_CRITICAL_COUNT`, `AC_MOBSF_NORMAL_COUNT`,
  `AC_MOBSF_LOW_COUNT`: Finding counts per level.
- `AC_MOBSF_WORST_LEVEL`: `critical`, `normal`, `low`, or `none`.

No report path is exported: the report is written straight into `$AC_OUTPUT_DIR` under a fixed
name, so a following step already knows where it is.

## Reports

The report is published directly into `$AC_OUTPUT_DIR` as `mobsf-binary-analyze.json`, under its
own name and unarchived, so add Export Build Artifacts after this step. It is published on the
failing path too, so a broken gate still leaves the findings downloadable.

JSON is the only format MobSF reports here: its other export is a PDF, which needs
`wkhtmltopdf`, and that is not installed on the runners. There is therefore no output format
input on this step.

The build log closes with a summary, ending in the verdict:

```
  Artifact              app-release.apk
  Security score        35 / 100
  Critical              6 finding(s)
  Normal                3 finding(s)
  Low                   1 finding(s)
  Passed checks         2
  Needs review          0
  Total                 10 finding(s)
  Worst level found     Critical
  Fail build on         critical
  Minimum score         not set
  Verdict               pipeline breaks
```

## Notes

- **The whole MobSF interaction is one call.** `mobsf-control.sh --action scan` sources
  `mobsf.env`, starts MobSF if it is not already answering, uploads, scans, writes the report,
  and then removes the scan record, the uploaded artifact and the decompiled sources. That last
  part is why there is no rescan input: MobSF caches by artifact MD5, but the record never
  survives a build, so a stale scan cannot be returned.
- **An AAB is supported.** MobSF converts it to an APK with the bundletool it ships, using the
  provisioned Java.
- **An `.xcarchive` is not an artifact.** The step says so rather than handing MobSF something
  it cannot read; export the `.ipa` first.
- A failed decompilation is not a failed scan. MobSF judges jadx by its exit code and jadx exits
  non-zero as soon as one class fails, which is routine for an R8 build. The step reads the
  report rather than the tool's verdict.

## Running tests

Requires the [RSpec](https://rspec.info) gem and the Ruby standard library. No Gemfile or
Bundler needed.

```bash
ruby test/test_main.rb
```

The end to end examples run `main.rb` the way the runner does, against a stand-in
`mobsf-control.sh` planted the way a real runner is laid out, so no provisioned MobSF is needed.

## Contributing

Source: https://github.com/appcircleio/appcircle-mobsf-binary-scan
