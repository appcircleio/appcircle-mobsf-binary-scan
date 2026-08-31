require 'json'
require 'open3'
require 'pathname'
require 'fileutils'
require 'shellwords'

###### Defaults & Constants
DEFAULT_FAIL_ON = "critical"
DEFAULT_MINIMUM_SCORE = 0
DEFAULT_SCAN_TIMEOUT = 1800
CONTROL_TIMEOUT_MARGIN = 60

SEVERITIES = ["ERROR", "WARNING", "INFO"]
SEVERITY_RANK = {"INFO" => 1, "WARNING" => 2, "ERROR" => 3}

FAIL_ON_LEVELS = ["critical", "normal", "low", "none"]
LEVEL_SEVERITY = {"critical" => "ERROR", "normal" => "WARNING", "low" => "INFO"}

MOBSF_SEVERITY_MAP = {"high" => "ERROR", "warning" => "WARNING", "info" => "INFO"}
MOBSF_NON_FINDING_BUCKETS = ["secure", "hotspot"]

SEVERITY_LABEL = {"ERROR" => "Critical", "WARNING" => "Normal", "INFO" => "Low"}

###### MobSF Installation
DEFAULT_MOBSF_PREFIXES = ["/usr/local/appcircle/mobsf", "/opt/appcircle/mobsf"]
MOBSF_MANIFEST_FILE = "appcircle-mobsf-manifest.json"
MOBSF_CONTROL_SCRIPT = "mobsf-control.sh"
MOBSF_REPORT_FILENAME = "mobsf-binary-analyze.json"

MOBSF_EXIT_USAGE = 2
MOBSF_EXIT_NOT_PROVISIONED = 3

###### Artifact
SUPPORTED_ARTIFACTS = [".apk", ".aab", ".ipa"]

ARTIFACT_PATH_VARIABLES = ["AC_APK_PATH", "AC_AAB_PATH"]
ARTIFACT_DIR_VARIABLES = ["AC_EXPORT_DIR", "AC_OUTPUT_DIR"]

###### Enviroment Variable Check
def env_has_key(key)
  return (ENV[key] != nil && ENV[key] != "") ? ENV[key] : abort("Missing #{key}.")
end

def env_default(key, default)
  return (ENV[key] != nil && ENV[key] != "") ? ENV[key].strip : default
end

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
READER_DRAIN_TIMEOUT = 2
REAP_TIMEOUT = 10
KILL_GRACE_TIMEOUT = 3
KILL_POLL_INTERVAL = 0.1

def monotonic_now()
  return Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

def run_command(command, skip_abort, timeout = nil)
  puts "@@[command] #{command.shelljoin}"

  stdout_str = ""
  stderr_str = ""

  begin
    stdin, stdout, stderr, wait_thr = Open3.popen3(*command, :pgroup => true)
  rescue Errno::ENOENT
    abort_script("#{command[0]} was not found on this runner.")
  end

  begin
    stdin.close
    readers = [read_stream(stdout, stdout_str), read_stream(stderr, stderr_str)]

    timed_out = wait_thr.join(timeout) == nil
    kill_process_group(wait_thr.pid) if timed_out
    stop_readers(readers, [stdout, stderr])
    status = wait_thr.join(REAP_TIMEOUT) != nil ? wait_thr.value : nil
  ensure
    [stdout, stderr].each { |io| io.close unless io.closed? }
  end

  if timed_out
    abort_script("`#{File.basename(command[0])}` exceeded the #{timeout} second timeout and was terminated.")
  end

  if status == nil
    abort_script("`#{File.basename(command[0])}` could not be terminated on this runner and did " \
                 "not report an exit code.")
  end

  unless status.success?
    abort_script(stderr_str) unless skip_abort
  end

  return stdout_str, stderr_str, status.exitstatus
end

def read_stream(io, buffer)
  return Thread.new do
    begin
      io.each_line { |line| buffer << line }
    rescue IOError, Errno::EBADF
    end
  end
end

def stop_readers(readers, streams)
  deadline = monotonic_now() + READER_DRAIN_TIMEOUT
  readers.each do |reader|
    remaining = deadline - monotonic_now()
    reader.join(remaining > 0 ? remaining : 0)
  end
  return if readers.none? { |reader| reader.alive? }

  streams.each { |io| io.close unless io.closed? }
  readers.each { |reader| reader.kill if reader.join(KILL_GRACE_TIMEOUT) == nil }
end

def kill_process_group(pid)
  return unless signal_process_group(pid, "TERM")

  deadline = monotonic_now() + KILL_GRACE_TIMEOUT
  while monotonic_now() < deadline
    return unless signal_process_group(pid, 0)

    sleep KILL_POLL_INTERVAL
  end

  signal_process_group(pid, "KILL")
end

def signal_process_group(pid, signal)
  begin
    Process.kill(signal, -pid)
    return true
  rescue Errno::ESRCH, Errno::EPERM
    return false
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
  unless configured =~ /\A\d+\z/ && timeout > 0
    abort_script("Invalid scan timeout `#{configured}`. A positive whole number of seconds is expected.")
  end

  return timeout
end

def get_minimum_score()
  configured = env_default("AC_MOBSF_MIN_SCORE", "#{DEFAULT_MINIMUM_SCORE}")
  score = configured.to_i
  unless configured =~ /\A\d+\z/ && score <= 100
    abort_script("Invalid minimum security score `#{configured}`. A whole number between 0 and 100 " \
                 "is expected.")
  end

  return score
end

###### Artifact Resolution
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
  print_summary_line("Minimum score", get_minimum_score_label(minimum_score))
  print_summary_line("Verdict", get_gate_failure(summary, fail_on, minimum_score) != nil ? "pipeline breaks" : "pipeline continues")
  puts "------------------------------------------------------"
end

def get_minimum_score_label(minimum_score)
  return "0 (no score gate)" if minimum_score == nil || minimum_score == 0

  return "#{minimum_score}"
end

###### Quality Gate
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

  begin
    FileUtils.mkdir_p($output_path)
    puts "Publishing #{MOBSF_REPORT_FILENAME} to #{$output_path}"
    FileUtils.cp($report_path, "#{$output_path}/#{MOBSF_REPORT_FILENAME}")
  rescue Exception => e
    abort_script(e)
  end

  return $output_path
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

def get_step_outputs(summary, artifact)
  return {
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

copy_report() if $save_report
write_environment_variables(get_step_outputs($summary, $artifact))

$failure = get_gate_failure($summary, $fail_on, $minimum_score)
if $failure != nil
  abort_script("#{$failure}, which breaks the pipeline. The report is still published as an artifact.")
end

puts "MobSF found nothing that breaks the pipeline."

exit 0

end # if __FILE__ == $PROGRAM_NAME
