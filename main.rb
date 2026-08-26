# Appcircle MobSF Binary Scan component.
#
# Runs full MobSF static analysis on a compiled artifact (APK, AAB or IPA)
# using the MobSF installation the runner was provisioned with (PL-398).
#
# MobSF is GPL-3.0-only, so it is never downloaded or redistributed by this
# step: the step only locates what provisioning left on the runner and drives
# it through `mobsf-control.sh`. A runner without MobSF is an error here, not a
# fallback, because binary analysis has no CLI equivalent.
#
# Only Ruby stdlib is used, steps run against the runner's system Ruby without
# Bundler.

require 'json'
require 'open3'
require 'pathname'
require 'fileutils'
require 'shellwords'

###### Defaults & Constants
DEFAULT_FAIL_ON = "critical"
DEFAULT_SCAN_TIMEOUT = 1800
CONTROL_TIMEOUT_MARGIN = 60

SEVERITIES = ["ERROR", "WARNING", "INFO"]
SEVERITY_RANK = {"INFO" => 1, "WARNING" => 2, "ERROR" => 3}

# The gate speaks the vocabulary the step form offers, mapped onto what MobSF
# reports. `none` never breaks the pipeline.
FAIL_ON_LEVELS = ["critical", "normal", "low", "none"]
LEVEL_SEVERITY = {"critical" => "ERROR", "normal" => "WARNING", "low" => "INFO"}

# MobSF grades findings as high/warning/info/secure/hotspot. Only the first
# three are failures. `secure` is a passed check and `hotspot` needs a human,
# so neither counts towards the gate.
MOBSF_SEVERITY_MAP = {"high" => "ERROR", "warning" => "WARNING", "info" => "INFO"}
MOBSF_NON_FINDING_BUCKETS = ["secure", "hotspot"]

# The build log speaks the same words as the step form rather than MobSF's
# internal grades, so the level a user picked reads back unchanged.
SEVERITY_LABEL = {"ERROR" => "Critical", "WARNING" => "Normal", "INFO" => "Low"}

###### MobSF Installation
# Provisioning puts MobSF here: macOS first, then Linux.
DEFAULT_MOBSF_PREFIXES = ["/usr/local/appcircle/mobsf", "/opt/appcircle/mobsf"]
MOBSF_MANIFEST_FILE = "appcircle-mobsf-manifest.json"
MOBSF_CONTROL_SCRIPT = "mobsf-control.sh"
MOBSF_REPORT_FILENAME = "mobsf-report.json"
MOBSF_OUTPUT_DIRNAME = "mobsf_output"

# mobsf-control.sh exit codes that the step reacts to.
MOBSF_EXIT_USAGE = 2
MOBSF_EXIT_NOT_PROVISIONED = 3

###### Artifact
# MobSF scans these. An AAB is converted to an APK with the bundletool that
# ships inside MobSF, using the provisioned Java.
SUPPORTED_ARTIFACTS = [".apk", ".aab", ".ipa"]

# Checked in order when the artifact path input is left empty. Android exposes
# the built binary directly, iOS exposes only the export directory.
ARTIFACT_PATH_VARIABLES = ["AC_APK_PATH", "AC_AAB_PATH"]
ARTIFACT_DIR_VARIABLES = ["AC_EXPORT_DIR", "AC_OUTPUT_DIR"]

###### Enviroment Variable Check
def env_has_key(key)
  return (ENV[key] != nil && ENV[key] != "") ? ENV[key] : abort("Missing #{key}.")
end

def env_default(key, default)
  return (ENV[key] != nil && ENV[key] != "") ? ENV[key].strip : default
end

# The report is written here, and the runner discards it when the build ends.
def get_step_temp()
  step_temp = env_default("AC_STEP_TEMP", nil)
  return step_temp if step_temp != nil

  temp_dir = env_default("AC_TEMP_DIR", nil)
  if temp_dir == nil
    abort("Missing AC_STEP_TEMP or AC_TEMP_DIR.")
  end

  return "#{temp_dir}/appcircle_mobsf_binary_scan"
end

if __FILE__ == $PROGRAM_NAME

$step_temp = get_step_temp()
$output_path = ENV["AC_OUTPUT_DIR"]
$env_file_path = ENV["AC_ENV_FILE_PATH"]
$report_path = "#{$step_temp}/#{MOBSF_REPORT_FILENAME}"

#save_report - Options: true, false
$save_report = env_default("AC_MOBSF_SAVE_REPORT", "true") != "false"

end # if __FILE__ == $PROGRAM_NAME

###### Abort Function
def abort_script(error)
  abort("@@[error] #{error}")
end

###### Run Command Function
# The command is an argv array and is never handed to a shell, so a path with
# a space or a shell metacharacter cannot be reinterpreted.
# Returns stdout, stderr and the exit code.
def run_command(command, skip_abort, timeout = nil)
  puts "@@[command] #{command.shelljoin}"

  stdout_str = ""
  stderr_str = ""
  status = nil

  begin
    Open3.popen3(*command, :pgroup => true) do |stdin, stdout, stderr, wait_thr|
      stdin.close
      readers = [
        Thread.new { stdout.each_line { |line| stdout_str += line } },
        Thread.new { stderr.each_line { |line| stderr_str += line } }
      ]

      if timeout != nil && wait_thr.join(timeout) == nil
        kill_process_group(wait_thr.pid)
        readers.each { |reader| reader.kill }
        abort_script("`#{File.basename(command[0])}` exceeded the #{timeout} second timeout and was terminated.")
      end

      readers.each { |reader| reader.join }
      status = wait_thr.value
    end
  rescue Errno::ENOENT
    abort_script("#{command[0]} was not found on this runner.")
  end

  unless status.success?
    abort_script(stderr_str) unless skip_abort
  end

  return stdout_str, stderr_str, status.exitstatus
end

# A stuck scan must never hang the build, so the whole process group goes down.
def kill_process_group(pid)
  begin
    Process.kill("TERM", -pid)
    sleep 3
    Process.kill("KILL", -pid)
  rescue Errno::ESRCH, Errno::EPERM
    return
  end
end

###### Input Parsing
#fail_on - Options: critical, normal, low, none
def get_fail_on()
  level = env_default("AC_MOBSF_FAIL_ON", DEFAULT_FAIL_ON).downcase
  unless FAIL_ON_LEVELS.include?(level)
    abort_script("Invalid fail build on level `#{level}`. Supported values: #{FAIL_ON_LEVELS.join(", ")}.")
  end

  return level
end

def get_scan_timeout()
  configured = env_default("AC_MOBSF_SCAN_TIMEOUT", "#{DEFAULT_SCAN_TIMEOUT}")
  timeout = configured.to_i
  unless timeout > 0
    abort_script("Invalid scan timeout `#{configured}`. A positive number of seconds is expected.")
  end

  return timeout
end

# Empty means no score gate. MobSF scores out of 100.
def get_minimum_score()
  configured = env_default("AC_MOBSF_MIN_SCORE", nil)
  return nil if configured == nil

  score = configured.to_i
  unless configured =~ /\A\d+\z/ && score <= 100
    abort_script("Invalid minimum security score `#{configured}`. A number between 0 and 100 is expected.")
  end

  return score
end

###### Artifact Resolution
# The input wins when it is set, and it accepts either the artifact or the
# directory holding it, because an iOS workflow only exposes the export
# directory. Otherwise the standard build variables are tried in turn.
def get_artifact_path()
  configured = env_default("AC_MOBSF_ARTIFACT_PATH", nil)
  return resolve_artifact(configured, "the artifact path input") if configured != nil

  ARTIFACT_PATH_VARIABLES.each do |key|
    value = env_default(key, nil)
    next if value == nil || !File.exist?(value)

    puts "Using the artifact from #{key}"
    return resolve_artifact(value, key)
  end

  ARTIFACT_DIR_VARIABLES.each do |key|
    value = env_default(key, nil)
    next if value == nil || !File.directory?(value)

    found = find_artifacts(value)
    next if found.empty?

    puts "Found the artifact under #{key}"
    return pick_single_artifact(found, value)
  end

  abort_script("No artifact to scan. Set the artifact path input, or run this step after " \
               "`Android Build` or `Xcodebuild for Devices` so that #{ARTIFACT_PATH_VARIABLES.join(", ")} " \
               "or an .ipa under #{ARTIFACT_DIR_VARIABLES.join(" / ")} is available.")
end

def resolve_artifact(path, origin)
  expanded = File.expand_path(path)
  unless File.exist?(expanded)
    abort_script("The artifact from #{origin} does not exist: #{expanded}")
  end

  return pick_single_artifact(find_artifacts(expanded), expanded) if File.directory?(expanded)

  extension = File.extname(expanded).downcase
  unless SUPPORTED_ARTIFACTS.include?(extension)
    abort_script("MobSF cannot scan `#{extension}` files. Supported: #{SUPPORTED_ARTIFACTS.join(", ")}. " \
                 "An .xcarchive is not an artifact, export the .ipa first.")
  end

  return expanded
end

def find_artifacts(directory)
  found = []
  SUPPORTED_ARTIFACTS.each do |extension|
    found.concat(Dir.glob("#{directory}/*#{extension}"))
  end

  return found.sort
end

def pick_single_artifact(found, directory)
  if found.empty?
    abort_script("No APK, AAB or IPA found in #{directory}.")
  end

  if found.length > 1
    puts "@@[warning] #{found.length} artifacts found in #{directory}, scanning the first one. " \
         "Set the artifact path input to choose: #{found.map { |f| File.basename(f) }.join(", ")}"
  end

  return found[0]
end

###### MobSF Discovery
# The prefix comes from MOBSF_HOME, then the well known provisioning paths.
def get_mobsf_prefix()
  candidates = []
  mobsf_home = env_default("MOBSF_HOME", nil)
  candidates.push(mobsf_home) if mobsf_home != nil
  candidates.concat(DEFAULT_MOBSF_PREFIXES)

  candidates.each do |prefix|
    return prefix if File.file?("#{prefix}/#{MOBSF_MANIFEST_FILE}")
  end

  return nil
end

def read_mobsf_manifest(prefix)
  begin
    return JSON.parse(File.read("#{prefix}/#{MOBSF_MANIFEST_FILE}"))
  rescue JSON::ParserError, Errno::ENOENT => e
    puts "@@[warning] The MobSF manifest under #{prefix} could not be read: #{e.message}"
    return nil
  end
end

def get_mobsf_control(prefix)
  get_mobsf_control_candidates(prefix).each do |candidate|
    return candidate if File.file?(candidate)
  end

  return nil
end

# mobsf-control.sh ships with the runner package rather than under the MobSF
# prefix, and the runner directory is not exposed as a build variable. On a dev
# macOS runner MobSF sits at /usr/local/appcircle/mobsf while the script is at
# <runner>/scripts, so every ancestor of the prefix and of the step's own
# working directory is checked for a scripts/ directory.
def get_mobsf_control_candidates(prefix)
  candidates = ["#{prefix}/#{MOBSF_CONTROL_SCRIPT}"]

  roots = [prefix, $step_temp, env_default("AC_TEMP_DIR", nil)]
  roots.compact.each do |root|
    ancestor_directories(root).each do |dir|
      candidates.push("#{dir}/scripts/#{MOBSF_CONTROL_SCRIPT}")
    end
  end

  ENV["PATH"].to_s.split(File::PATH_SEPARATOR).each do |dir|
    next if dir.empty?

    candidates.push("#{dir}/#{MOBSF_CONTROL_SCRIPT}")
  end

  return candidates.uniq
end

# The path itself and each of its parents, bounded so a pathological path
# cannot spin.
def ancestor_directories(path, limit = 12)
  directories = []
  current = File.expand_path(path)
  limit.times do
    directories.push(current)
    parent = File.dirname(current)
    break if parent == current

    current = parent
  end

  return directories
end

# Binary analysis has no CLI fallback, so a runner without MobSF fails the
# step with the provisioning script named rather than degrading silently.
def require_mobsf_installation()
  prefix = get_mobsf_prefix()
  if prefix == nil
    abort_script("No MobSF installation found on this runner (looked for #{MOBSF_MANIFEST_FILE} under " \
                 "#{DEFAULT_MOBSF_PREFIXES.join(", ")}). Provision it with `setup-mobsf.sh --prefix <path>` " \
                 "during runner setup. This step cannot install MobSF itself, its license does not allow it.")
  end

  manifest = read_mobsf_manifest(prefix)
  puts "Found MobSF #{manifest["mobsfVersion"]} at #{prefix}" if manifest != nil

  control = get_mobsf_control(prefix)
  if control == nil
    abort_script("MobSF is installed at #{prefix} but #{MOBSF_CONTROL_SCRIPT} was not found in the " \
                 "#{get_mobsf_control_candidates(prefix).length} locations searched under " \
                 "#{[prefix, $step_temp].compact.join(", ")} and PATH. It ships with the runner " \
                 "package, so this runner may predate it.")
  end

  return prefix, control
end

###### Scan
def get_scan_command(control, prefix, artifact, report_path, timeout)
  return [control, "--action", "scan",
          "--file", artifact,
          "--prefix", prefix,
          "--output", report_path,
          "--scan-timeout", "#{timeout}"]
end

# Translates the control script's documented exit codes into an actionable line.
def get_scan_failure_message(exit_code, stderr_str)
  case exit_code
  when MOBSF_EXIT_NOT_PROVISIONED
    return "The MobSF installation is incomplete. Check it with `setup-mobsf.sh --action status` on the runner."
  when MOBSF_EXIT_USAGE
    return "The MobSF control script rejected the arguments the step passed. This is a step bug, please report it."
  else
    return "The MobSF scan failed.\n#{stderr_str}"
  end
end

# The control script sources mobsf.env, starts MobSF if it is not already
# answering, uploads, scans, writes the report, and removes the scan record,
# the uploaded artifact and the decompiled sources afterwards. That last part
# is why this step needs no rescan input: a cached scan cannot survive a build.
def run_scan(control, prefix, artifact, timeout)
  puts "Scanning #{File.basename(artifact)} with MobSF"
  command = get_scan_command(control, prefix, artifact, $report_path, timeout)
  stdout_str, stderr_str, exit_code = run_command(command, true, timeout + CONTROL_TIMEOUT_MARGIN)
  puts stdout_str unless stdout_str.strip.empty?

  unless exit_code == 0
    abort_script(get_scan_failure_message(exit_code, stderr_str))
  end

  return parse_report($report_path)
end

###### Report
def parse_report(path)
  unless File.file?(path)
    abort_script("MobSF did not produce a report at #{path}.")
  end

  begin
    return JSON.parse(File.read(path))
  rescue JSON::ParserError => e
    abort_script("The MobSF report at #{path} could not be parsed: #{e.message}")
  end
end

def new_severity_counter()
  counter = {}
  SEVERITIES.each { |severity| counter[severity] = 0 }
  return counter
end

def bucket_length(appsec, bucket)
  return appsec[bucket] != nil ? appsec[bucket].length : 0
end

# `appsec` is the one section with the same shape for APK and IPA, so it is
# what the gate reads. MobSF folds its code analysis findings into it, mapping
# a `good` severity onto `secure`, so nothing is lost by reading only appsec.
def summarize_report(report)
  appsec = report["appsec"]
  if appsec == nil
    abort_script("The MobSF report holds no `appsec` section, so there is nothing to grade. " \
                 "The raw report is at #{$report_path}.")
  end

  findings = new_severity_counter()
  MOBSF_SEVERITY_MAP.each do |mobsf_severity, severity|
    findings[severity] += bucket_length(appsec, mobsf_severity)
  end

  totals = {}
  total = 0
  highest = nil
  SEVERITIES.each do |severity|
    totals[severity] = findings[severity]
    total += totals[severity]
    highest = severity if highest == nil && totals[severity] > 0
  end

  extras = {}
  MOBSF_NON_FINDING_BUCKETS.each { |bucket| extras[bucket] = bucket_length(appsec, bucket) }

  return {
    :findings => findings,
    :totals => totals,
    :total => total,
    :highest => highest,
    :extras => extras,
    :security_score => appsec["security_score"],
    :trackers => appsec["total_trackers"]
  }
end

def print_summary_line(label, value)
  puts "  #{label.ljust(22)}#{value}"
end

def print_summary(summary, artifact, fail_on, minimum_score)
  puts "------------------------------------------------------"
  puts "MobSF Binary Scan Summary"
  print_summary_line("Artifact", File.basename(artifact))
  print_summary_line("Security score", "#{summary[:security_score]} / 100")
  SEVERITIES.each do |severity|
    print_summary_line(SEVERITY_LABEL[severity], "#{summary[:findings][severity]} finding(s)")
  end
  print_summary_line("Passed checks", "#{summary[:extras]["secure"]}")
  print_summary_line("Needs review", "#{summary[:extras]["hotspot"]}")
  print_summary_line("Trackers", "#{summary[:trackers]}") if summary[:trackers] != nil
  print_summary_line("Total", "#{summary[:total]} finding(s)")
  print_summary_line("Worst level found", summary[:highest] != nil ? SEVERITY_LABEL[summary[:highest]] : "none")
  print_summary_line("Fail build on", fail_on == "none" ? "none (report only)" : fail_on)
  print_summary_line("Minimum score", minimum_score != nil ? "#{minimum_score}" : "not set")
  print_summary_line("Verdict", get_gate_failure(summary, fail_on, minimum_score) != nil ? "pipeline breaks" : "pipeline continues")
  puts "------------------------------------------------------"
end

###### Quality Gate
# Fails on a finding at the selected level or worse, so `low` is the strictest
# setting and `critical` the loosest, and on a score below the minimum.
# Returns the reason, or nil when the pipeline continues.
def get_gate_failure(summary, fail_on, minimum_score)
  if minimum_score != nil && summary[:security_score] != nil &&
     summary[:security_score] < minimum_score
    return "the security score #{summary[:security_score]} is below the required #{minimum_score}"
  end

  return nil if fail_on == "none"

  severity = LEVEL_SEVERITY[fail_on]
  abort_script("Unknown fail build on level `#{fail_on}`.") if severity == nil

  minimum = SEVERITY_RANK[severity]
  breached = SEVERITIES.any? { |s| SEVERITY_RANK[s] >= minimum && summary[:totals][s] > 0 }
  return "MobSF found a `#{fail_on}` finding or worse" if breached

  return nil
end

###### Report Publishing & Environment Variables
def copy_report()
  if $output_path == nil
    puts "@@[warning] AC_OUTPUT_DIR is not set, the report is not published as an artifact."
    return nil
  end

  export_path = (Pathname.new $output_path).join(MOBSF_OUTPUT_DIRNAME).to_s
  begin
    FileUtils.mkdir_p(export_path)
    puts "Copying #{MOBSF_REPORT_FILENAME} to #{export_path}"
    FileUtils.cp($report_path, "#{export_path}/#{MOBSF_REPORT_FILENAME}")
  rescue Exception => e
    abort_script(e)
  end

  return export_path
end

def write_environment_variables(values)
  if $env_file_path == nil
    puts "@@[warning] AC_ENV_FILE_PATH is not set, the step outputs are not exported."
    return
  end

  begin
    open($env_file_path, 'a') { |f|
      values.each { |key, value| f.puts "#{key}=#{value}" }
    }
  rescue Exception => e
    abort_script(e)
  end
end

def get_step_outputs(summary, report_dir, artifact)
  return {
    "AC_MOBSF_REPORT_PATH" => "#{report_dir}/#{MOBSF_REPORT_FILENAME}",
    "AC_MOBSF_SCANNED_ARTIFACT" => artifact,
    "AC_MOBSF_SECURITY_SCORE" => summary[:security_score],
    "AC_MOBSF_FINDING_COUNT" => summary[:total],
    "AC_MOBSF_CRITICAL_COUNT" => summary[:totals]["ERROR"],
    "AC_MOBSF_NORMAL_COUNT" => summary[:totals]["WARNING"],
    "AC_MOBSF_LOW_COUNT" => summary[:totals]["INFO"],
    "AC_MOBSF_WORST_LEVEL" => summary[:highest] != nil ? SEVERITY_LABEL[summary[:highest]].downcase : "none"
  }
end

###############################################################

if __FILE__ == $PROGRAM_NAME

$fail_on = get_fail_on()
$scan_timeout = get_scan_timeout()
$minimum_score = get_minimum_score()
$artifact = get_artifact_path()

FileUtils.mkdir_p($step_temp)

$prefix, $control = require_mobsf_installation()
$report = run_scan($control, $prefix, $artifact, $scan_timeout)
$summary = summarize_report($report)
print_summary($summary, $artifact, $fail_on, $minimum_score)

$export_path = $save_report ? copy_report() : nil
$report_dir = $export_path != nil ? $export_path : File.dirname($report_path)
write_environment_variables(get_step_outputs($summary, $report_dir, $artifact))

### The report is published either way, so a failing gate still leaves the
### findings downloadable.
$failure = get_gate_failure($summary, $fail_on, $minimum_score)
if $failure != nil
  abort_script("#{$failure}, which breaks the pipeline. The report is still published as an artifact.")
end

puts "MobSF found nothing that breaks the pipeline."

exit 0

end # if __FILE__ == $PROGRAM_NAME
