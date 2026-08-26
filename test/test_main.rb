# ─── Dependencies ─────────────────────────────────────────────────────────────
require 'rspec'
require 'rspec/core/formatters/base_formatter'
require 'fileutils'
require 'json'
require 'open3'
require 'stringio'
require 'tmpdir'

MAIN_RB = File.expand_path('../main.rb', __dir__)

# ─── Custom Formatter ─────────────────────────────────────────────────────────
class ReadableFormatter < RSpec::Core::Formatters::BaseFormatter
  RSpec::Core::Formatters.register(
    self,
    :example_group_started,
    :example_group_finished,
    :example_passed,
    :example_failed,
    :example_pending,
    :dump_summary
  )

  PASS  = "\e[32;1m[ PASS ]\e[0m"
  FAIL  = "\e[31;1m[ FAIL ]\e[0m"
  ERROR = "\e[31;1m[ERROR ]\e[0m"
  SKIP  = "\e[33;1m[ SKIP ]\e[0m"

  DIVIDER     = "\e[90m#{'─' * 72}\e[0m"
  DIVIDER_FAT = "\e[90m#{'═' * 72}\e[0m"

  GROUP_COLORS = [
    "\e[34;1m",
    "\e[35;1m",
    "\e[36;1m",
    "\e[33;1m",
  ].freeze

  def initialize(output)
    super
    @depth    = 0
    @top_idx  = -1
    @failures = []
    @counts   = { passed: 0, failed: 0, pending: 0 }
  end

  def example_group_started(notification)
    group = notification.group
    if group.parent_groups.size <= 1
      output.puts if @depth.zero?
      @top_idx = (@top_idx + 1) % GROUP_COLORS.size
      output.puts "  #{GROUP_COLORS[@top_idx]}#{group.description}\e[0m"
    else
      output.puts "    #{'  ' * (@depth - 1)}\e[90m▸ \e[0m\e[37m#{group.description}\e[0m"
    end
    @depth += 1
  end

  def example_group_finished(_notification)
    @depth -= 1 if @depth > 0
  end

  def example_passed(notification)
    @counts[:passed] += 1
    print_example(PASS, notification.example)
  end

  def example_failed(notification)
    @counts[:failed] += 1
    ex    = notification.example
    exc   = ex.execution_result.exception
    badge = exc.is_a?(RSpec::Expectations::ExpectationNotMetError) ? FAIL : ERROR
    print_example(badge, ex)
    @failures << notification
  end

  def example_pending(notification)
    @counts[:pending] += 1
    ex = notification.example
    output.puts "    #{'  ' * [0, @depth - 1].max}#{SKIP}  #{ex.description}"
  end

  def dump_summary(notification)
    output.puts
    output.puts DIVIDER_FAT

    unless @failures.empty?
      output.puts "\n  \e[1;31mFailures:\e[0m\n"
      @failures.each_with_index do |n, i|
        ex  = n.example
        exc = ex.execution_result.exception
        output.puts "  \e[1m#{i + 1}) #{ex.full_description}\e[0m"
        exc.message.lines.first(6).each { |line| output.puts "     \e[31m#{line.rstrip}\e[0m" }
        output.puts "     \e[90m# #{ex.location}\e[0m"
        output.puts
      end
      output.puts DIVIDER
    end

    t   = notification.examples.size
    p   = @counts[:passed]
    f   = @counts[:failed]
    s   = @counts[:pending]
    sec = format('%.3fs', notification.duration)

    parts = ["\e[32m#{p} passed\e[0m"]
    parts << "\e[31m#{f} failed\e[0m"  if f > 0
    parts << "\e[33m#{s} pending\e[0m" if s > 0

    overall = f.zero? ? "\e[32;1m✔  All #{t} tests passed\e[0m" : "\e[31;1m✖  #{f} of #{t} tests failed\e[0m"
    output.puts "\n  #{overall}"
    output.puts "  #{parts.join('  |  ')}  \e[90m(#{sec})\e[0m"
    output.puts DIVIDER_FAT
  end

  private

  def print_example(badge, example)
    indent = '  ' * [0, @depth - 1].max
    time   = format('%.3fs', example.execution_result.run_time)
    output.puts "    #{indent}#{badge}  #{example.description}  \e[90m(#{time})\e[0m"
  end
end

# ─── Load main.rb (top-level execution is guarded by __FILE__ == $PROGRAM_NAME)
require_relative '../main.rb'

# ─── Global State Helpers ─────────────────────────────────────────────────────
# main.rb keeps its configuration in globals that are assigned only when it runs
# as the main script, so the unit tests set them directly.
INPUT_KEYS = %w[
  AC_STEP_TEMP AC_TEMP_DIR AC_OUTPUT_DIR AC_ENV_FILE_PATH AC_EXPORT_DIR
  AC_APK_PATH AC_AAB_PATH MOBSF_HOME
  AC_MOBSF_ARTIFACT_PATH AC_MOBSF_FAIL_ON AC_MOBSF_MIN_SCORE
  AC_MOBSF_SCAN_TIMEOUT AC_MOBSF_SAVE_REPORT
].freeze

def reset_inputs
  INPUT_KEYS.each { |key| ENV.delete(key) }
  $step_temp = nil
  $output_path = nil
  $env_file_path = nil
  $report_path = nil
  $save_report = true
end

# abort_script writes to $stderr and raises SystemExit. Returns the message, or
# nil when the block did not abort.
def capture_abort
  buffer = StringIO.new
  original = $stderr
  $stderr = buffer
  aborted = false
  begin
    yield
  rescue SystemExit
    aborted = true
  ensure
    $stderr = original
  end
  return aborted ? buffer.string : nil
end

def capture_stdout
  buffer = StringIO.new
  original = $stdout
  $stdout = buffer
  begin
    yield
  ensure
    $stdout = original
  end
  return buffer.string
end

# ─── Report Helpers ───────────────────────────────────────────────────────────
def appsec_report(high: 0, warning: 0, info: 0, secure: 0, hotspot: 0, score: 67, trackers: 0)
  entries = ->(count) { Array.new(count) { |i| { 'title' => "finding #{i}", 'section' => 'code' } } }
  {
    'appsec' => {
      'security_score' => score,
      'high' => entries.call(high),
      'warning' => entries.call(warning),
      'info' => entries.call(info),
      'secure' => entries.call(secure),
      'hotspot' => entries.call(hotspot),
      'total_trackers' => trackers
    }
  }
end

def touch_artifact(dir, name)
  FileUtils.mkdir_p(dir)
  path = File.join(dir, name)
  File.write(path, 'binary')
  return path
end

# ─── Fake MobSF Runner Helper ─────────────────────────────────────────────────
# There is no provisioned MobSF on a dev machine, so the scan is driven against
# a stand-in mobsf-control.sh honouring the documented contract: it validates
# the arguments, writes the report to --output and returns one of the documented
# exit codes.
#
# It is planted the way a real runner is laid out, with MobSF under its own
# prefix and the control script in a scripts/ directory further up, so the
# step's own discovery has to find both. The step exposes no path inputs.
def plant_fake_mobsf(workspace, report, exit_code)
  prefix = File.join(workspace, 'mobsf')
  FileUtils.mkdir_p(prefix)
  File.write(File.join(prefix, 'appcircle-mobsf-manifest.json'),
             JSON.dump({ 'schemaVersion' => 1, 'mobsfVersion' => '4.5.2',
                         'listenPort' => 8000, 'prefix' => prefix }))

  scripts = File.join(workspace, 'scripts')
  FileUtils.mkdir_p(scripts)
  control = File.join(scripts, 'mobsf-control.sh')
  payload = File.join(workspace, 'canned-report.json')
  File.write(payload, JSON.dump(report)) if report

  File.write(control, <<~SH)
    #!/bin/sh
    echo "$@" > "#{workspace}/last-args"
    output=""
    file=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --output) output="$2"; shift 2 ;;
        --file) file="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    echo "$file" > "#{workspace}/received-file"
    if [ #{exit_code} -ne 0 ]; then
      echo "fake mobsf failure" >&2
      exit #{exit_code}
    fi
    cp "#{payload}" "$output"
    echo "[MobSF] AppSec summary written"
    exit 0
  SH
  FileUtils.chmod(0o755, control)

  return prefix
end

# ─── Subprocess Helper ────────────────────────────────────────────────────────
# Runs main.rb in a child process with a controlled ENV, the way the runner does.
# Nil values explicitly unset keys inherited from the parent process.
def run_main(env = {}, fake_mobsf = nil)
  Dir.mktmpdir do |workspace|
    step_temp = File.join(workspace, 'step_temp')
    output_dir = File.join(workspace, 'output')
    env_file = File.join(workspace, 'env_file')
    FileUtils.mkdir_p([step_temp, output_dir])
    FileUtils.touch(env_file)

    mobsf_env = {}
    if fake_mobsf
      mobsf_env['MOBSF_HOME'] =
        plant_fake_mobsf(workspace, fake_mobsf[:report], fake_mobsf.fetch(:exit_code, 0))
    end

    clean_env = INPUT_KEYS.each_with_object({}) { |key, acc| acc[key] = nil }
                          .merge('AC_STEP_TEMP' => step_temp,
                                 'AC_TEMP_DIR' => step_temp,
                                 'AC_OUTPUT_DIR' => output_dir,
                                 'AC_ENV_FILE_PATH' => env_file)
                          .merge(mobsf_env)
                          .merge(env)
                          .reject { |_, value| value.nil? }

    stdout_str, stderr_str, status = Open3.capture3(clean_env, "ruby #{MAIN_RB}")
    outputs = {}
    File.readlines(env_file, chomp: true).reject(&:empty?).each do |line|
      key, value = line.split('=', 2)
      outputs[key] = value
    end

    received = File.join(workspace, 'received-file')
    args = File.join(workspace, 'last-args')
    yield({
      stdout: stdout_str,
      stderr: stderr_str,
      success: status.success?,
      outputs: outputs,
      workspace: workspace,
      output_dir: File.join(output_dir, 'mobsf_output'),
      mobsf_args: File.file?(args) ? File.read(args).strip : nil,
      scanned_file: File.file?(received) ? File.read(received).strip : nil
    })
  end
end

# ─── Tests ────────────────────────────────────────────────────────────────────

# ─── 1. get_fail_on ───────────────────────────────────────────────────────────
RSpec.describe '#get_fail_on' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'defaults to critical' do
      expect(get_fail_on).to eq('critical')
    end

    it 'downcases an explicit value' do
      ENV['AC_MOBSF_FAIL_ON'] = 'NONE'
      expect(get_fail_on).to eq('none')
    end
  end

  context 'negative path – unsupported value' do
    it 'aborts and names the supported values' do
      ENV['AC_MOBSF_FAIL_ON'] = 'blocker'
      message = capture_abort { get_fail_on }
      expect(message).to include('blocker')
      expect(message).to include('critical, normal, low, none')
    end
  end
end

# ─── 2. get_scan_timeout ──────────────────────────────────────────────────────
RSpec.describe '#get_scan_timeout' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'defaults to 1800 seconds, above MobSF\'s own decompile and SAST timeouts' do
      expect(get_scan_timeout).to eq(1800)
    end

    it 'accepts an explicit value' do
      ENV['AC_MOBSF_SCAN_TIMEOUT'] = '600'
      expect(get_scan_timeout).to eq(600)
    end
  end

  context 'negative path' do
    it 'aborts on zero' do
      ENV['AC_MOBSF_SCAN_TIMEOUT'] = '0'
      expect { get_scan_timeout }.to raise_error(SystemExit)
    end

    it 'aborts on a non-numeric value' do
      ENV['AC_MOBSF_SCAN_TIMEOUT'] = 'soon'
      expect { get_scan_timeout }.to raise_error(SystemExit)
    end
  end
end

# ─── 3. get_minimum_score ─────────────────────────────────────────────────────
RSpec.describe '#get_minimum_score' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'is unset by default, so the score gate is off' do
      expect(get_minimum_score).to be_nil
    end

    it 'accepts a score in range' do
      ENV['AC_MOBSF_MIN_SCORE'] = '45'
      expect(get_minimum_score).to eq(45)
    end

    it 'accepts zero' do
      ENV['AC_MOBSF_MIN_SCORE'] = '0'
      expect(get_minimum_score).to eq(0)
    end
  end

  context 'negative path' do
    it 'aborts above 100, since MobSF scores out of 100' do
      ENV['AC_MOBSF_MIN_SCORE'] = '120'
      expect(capture_abort { get_minimum_score }).to include('between 0 and 100')
    end

    it 'aborts on a non-numeric value' do
      ENV['AC_MOBSF_MIN_SCORE'] = 'high'
      expect(capture_abort { get_minimum_score }).to include('between 0 and 100')
    end
  end
end

# ─── 4. get_artifact_path ─────────────────────────────────────────────────────
# Android exposes the built binary directly, iOS only the export directory, so
# the resolver accepts a file or a folder and falls back through the standard
# build variables.
RSpec.describe '#get_artifact_path' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path – explicit input' do
    it 'takes the artifact the input names' do
      Dir.mktmpdir do |dir|
        apk = touch_artifact(dir, 'app.apk')
        ENV['AC_MOBSF_ARTIFACT_PATH'] = apk
        expect(get_artifact_path).to eq(apk)
      end
    end

    it 'finds the artifact when the input names a folder' do
      Dir.mktmpdir do |dir|
        ipa = touch_artifact(dir, 'MyApp.ipa')
        ENV['AC_MOBSF_ARTIFACT_PATH'] = dir
        expect(capture_stdout { expect(get_artifact_path).to eq(ipa) }).to be_a(String)
      end
    end
  end

  context 'positive path – standard build variables' do
    it 'uses AC_APK_PATH' do
      Dir.mktmpdir do |dir|
        apk = touch_artifact(dir, 'app-release.apk')
        ENV['AC_APK_PATH'] = apk
        capture_stdout { expect(get_artifact_path).to eq(apk) }
      end
    end

    it 'uses AC_AAB_PATH when there is no APK' do
      Dir.mktmpdir do |dir|
        aab = touch_artifact(dir, 'app-release.aab')
        ENV['AC_AAB_PATH'] = aab
        capture_stdout { expect(get_artifact_path).to eq(aab) }
      end
    end

    it 'prefers the APK when both are set' do
      Dir.mktmpdir do |dir|
        apk = touch_artifact(dir, 'app.apk')
        touch_artifact(dir, 'app.aab')
        ENV['AC_APK_PATH'] = apk
        ENV['AC_AAB_PATH'] = File.join(dir, 'app.aab')
        capture_stdout { expect(get_artifact_path).to eq(apk) }
      end
    end

    # An iOS workflow exposes no IPA path, only the export directory.
    it 'finds the .ipa under AC_EXPORT_DIR' do
      Dir.mktmpdir do |dir|
        ipa = touch_artifact(dir, 'Appcircle.ipa')
        ENV['AC_EXPORT_DIR'] = dir
        capture_stdout { expect(get_artifact_path).to eq(ipa) }
      end
    end

    it 'falls back to AC_OUTPUT_DIR' do
      Dir.mktmpdir do |dir|
        ipa = touch_artifact(dir, 'Appcircle.ipa')
        ENV['AC_OUTPUT_DIR'] = dir
        capture_stdout { expect(get_artifact_path).to eq(ipa) }
      end
    end

    it 'warns and takes the first when a folder holds several artifacts' do
      Dir.mktmpdir do |dir|
        touch_artifact(dir, 'b.ipa')
        touch_artifact(dir, 'a.ipa')
        ENV['AC_EXPORT_DIR'] = dir
        log = capture_stdout { expect(get_artifact_path).to end_with('a.ipa') }
        expect(log).to include('@@[warning]')
        expect(log).to include('2 artifacts found')
      end
    end
  end

  context 'negative path' do
    it 'aborts naming the build steps when nothing is available' do
      Dir.mktmpdir do |dir|
        ENV['AC_EXPORT_DIR'] = dir
        message = capture_abort { get_artifact_path }
        expect(message).to include('Android Build')
        expect(message).to include('Xcodebuild for Devices')
      end
    end

    it 'aborts when the input names a missing file' do
      ENV['AC_MOBSF_ARTIFACT_PATH'] = '/nope/app.apk'
      expect(capture_abort { get_artifact_path }).to include('does not exist')
    end

    # An archive is not an artifact, and this is the mistake an iOS workflow
    # invites, since the archive is what lands in the output directory.
    it 'aborts on an unsupported extension and says to export the ipa' do
      Dir.mktmpdir do |dir|
        archive = touch_artifact(dir, 'build.xcarchive')
        ENV['AC_MOBSF_ARTIFACT_PATH'] = archive
        message = capture_abort { get_artifact_path }
        expect(message).to include('.xcarchive')
        expect(message).to include('export the .ipa')
      end
    end

    it 'aborts when the folder holds no artifact' do
      Dir.mktmpdir do |dir|
        ENV['AC_MOBSF_ARTIFACT_PATH'] = dir
        expect(capture_abort { get_artifact_path }).to include('No APK, AAB or IPA found')
      end
    end
  end
end

# ─── 5. MobSF discovery ───────────────────────────────────────────────────────
RSpec.describe '#get_mobsf_control' do
  before { reset_inputs }
  after { reset_inputs }

  def install_control(dir)
    FileUtils.mkdir_p(dir)
    path = File.join(dir, 'mobsf-control.sh')
    File.write(path, "#!/bin/sh\nexit 0\n")
    FileUtils.chmod(0o755, path)
    path
  end

  # A dev macOS runner has MobSF at /usr/local/appcircle/mobsf with the script
  # one level up, in the runner package.
  context 'positive path' do
    it 'finds the script in a scripts/ directory beside the prefix' do
      Dir.mktmpdir do |root|
        prefix = File.join(root, 'appcircle/mobsf')
        FileUtils.mkdir_p(prefix)
        expected = install_control(File.join(root, 'appcircle/scripts'))
        expect(get_mobsf_control(prefix)).to eq(expected)
      end
    end

    it 'finds the script from the step working directory' do
      Dir.mktmpdir do |root|
        prefix = File.join(root, 'elsewhere/mobsf')
        FileUtils.mkdir_p(prefix)
        $step_temp = File.join(root, 'runner/work/step_tmp')
        FileUtils.mkdir_p($step_temp)
        expected = install_control(File.join(root, 'runner/scripts'))
        expect(get_mobsf_control(prefix)).to eq(expected)
      end
    end
  end

  context 'negative path' do
    it 'returns nil when the script is nowhere to be found' do
      Dir.mktmpdir do |root|
        prefix = File.join(root, 'a/b/c/mobsf')
        FileUtils.mkdir_p(prefix)
        $step_temp = prefix
        expect(get_mobsf_control(prefix)).to be_nil
      end
    end
  end
end

RSpec.describe '#get_mobsf_prefix' do
  before { reset_inputs }
  after { reset_inputs }

  it 'uses MOBSF_HOME when it holds a manifest' do
    Dir.mktmpdir do |prefix|
      File.write(File.join(prefix, 'appcircle-mobsf-manifest.json'), '{}')
      ENV['MOBSF_HOME'] = prefix
      expect(get_mobsf_prefix).to eq(prefix)
    end
  end

  it 'returns nil when no manifest is present' do
    Dir.mktmpdir do |prefix|
      ENV['MOBSF_HOME'] = prefix
      expect(get_mobsf_prefix).to be_nil
    end
  end
end

# ─── 6. get_scan_command ──────────────────────────────────────────────────────
RSpec.describe '#get_scan_command' do
  it 'passes the documented mobsf-control.sh arguments' do
    command = get_scan_command('/r/scripts/mobsf-control.sh', '/p', '/out/app.apk', '/tmp/r.json', 900)
    expect(command[0]).to eq('/r/scripts/mobsf-control.sh')
    expect(command[command.index('--action'), 2]).to eq(%w[--action scan])
    expect(command[command.index('--file'), 2]).to eq(['--file', '/out/app.apk'])
    expect(command[command.index('--prefix'), 2]).to eq(['--prefix', '/p'])
    expect(command[command.index('--output'), 2]).to eq(['--output', '/tmp/r.json'])
    expect(command[command.index('--scan-timeout'), 2]).to eq(['--scan-timeout', '900'])
  end

  it 'keeps a path with spaces as one argument' do
    command = get_scan_command('/c.sh', '/p', '/out/My App.ipa', '/tmp/r.json', 60)
    expect(command).to include('/out/My App.ipa')
  end
end

# ─── 7. get_scan_failure_message ──────────────────────────────────────────────
RSpec.describe '#get_scan_failure_message' do
  it 'names setup-mobsf.sh for an incomplete installation (exit 3)' do
    expect(get_scan_failure_message(3, '')).to include('setup-mobsf.sh')
  end

  it 'calls a usage error a step bug (exit 2)' do
    expect(get_scan_failure_message(2, '')).to include('step bug')
  end

  it 'surfaces stderr for a runtime failure (exit 1)' do
    expect(get_scan_failure_message(1, 'jadx exploded')).to include('jadx exploded')
  end
end

# ─── 8. summarize_report ──────────────────────────────────────────────────────
RSpec.describe '#summarize_report' do
  context 'positive path' do
    let(:summary) { summarize_report(appsec_report(high: 2, warning: 3, info: 1, secure: 4, hotspot: 5, score: 42, trackers: 7)) }

    it 'maps high onto critical, warning onto normal and info onto low' do
      expect(summary[:findings]['ERROR']).to eq(2)
      expect(summary[:findings]['WARNING']).to eq(3)
      expect(summary[:findings]['INFO']).to eq(1)
    end

    it 'keeps the score and the tracker count' do
      expect(summary[:security_score]).to eq(42)
      expect(summary[:trackers]).to eq(7)
    end

    # A passed check and one needing review are not failures.
    it 'counts secure and hotspot outside the total' do
      expect(summary[:extras]['secure']).to eq(4)
      expect(summary[:extras]['hotspot']).to eq(5)
      expect(summary[:total]).to eq(6)
    end

    it 'reports the worst level found' do
      expect(summary[:highest]).to eq('ERROR')
    end

    it 'treats an empty appsec as a clean scan' do
      clean = summarize_report(appsec_report)
      expect(clean[:total]).to eq(0)
      expect(clean[:highest]).to be_nil
    end
  end

  context 'negative path – no appsec section' do
    it 'aborts rather than grading nothing' do
      expect(capture_abort { summarize_report({ 'type' => 'ios' }) }).to include('no `appsec` section')
    end
  end
end

# ─── 9. get_gate_failure ──────────────────────────────────────────────────────
RSpec.describe '#get_gate_failure' do
  let(:critical) { summarize_report(appsec_report(high: 1, score: 30)) }
  let(:normal) { summarize_report(appsec_report(warning: 2, score: 80)) }
  let(:low) { summarize_report(appsec_report(info: 1, score: 95)) }
  let(:clean) { summarize_report(appsec_report(score: 100)) }

  context 'positive path – pipeline continues' do
    it 'passes normal findings at the critical gate' do
      expect(get_gate_failure(normal, 'critical', nil)).to be_nil
    end

    it 'passes low findings at the normal gate' do
      expect(get_gate_failure(low, 'normal', nil)).to be_nil
    end

    it 'passes everything at none' do
      expect(get_gate_failure(critical, 'none', nil)).to be_nil
    end

    it 'passes a clean report at every level' do
      FAIL_ON_LEVELS.each { |level| expect(get_gate_failure(clean, level, nil)).to be_nil }
    end

    it 'passes when the score meets the minimum' do
      expect(get_gate_failure(low, 'none', 90)).to be_nil
    end
  end

  context 'negative path – pipeline breaks' do
    it 'fails on a critical finding at the critical gate' do
      expect(get_gate_failure(critical, 'critical', nil)).to include('`critical` finding or worse')
    end

    it 'fails on a normal finding at the normal gate' do
      expect(get_gate_failure(normal, 'normal', nil)).to include('`normal` finding or worse')
    end

    it 'fails on a low finding at the low gate' do
      expect(get_gate_failure(low, 'low', nil)).to include('`low` finding or worse')
    end

    # The score gate is independent, so it applies even in report only mode.
    it 'fails on a score below the minimum even when the level gate is none' do
      expect(get_gate_failure(critical, 'none', 50)).to include('30 is below the required 50')
    end
  end
end

# ─── 10. get_step_outputs ─────────────────────────────────────────────────────
RSpec.describe '#get_step_outputs' do
  let(:summary) { summarize_report(appsec_report(high: 1, warning: 2, info: 3, score: 55)) }

  it 'exports the report path, the artifact and the score' do
    outputs = get_step_outputs(summary, '/reports', '/out/app.apk')
    expect(outputs['AC_MOBSF_REPORT_PATH']).to eq('/reports/mobsf-report.json')
    expect(outputs['AC_MOBSF_SCANNED_ARTIFACT']).to eq('/out/app.apk')
    expect(outputs['AC_MOBSF_SECURITY_SCORE']).to eq(55)
  end

  it 'exports the counts in the form vocabulary' do
    outputs = get_step_outputs(summary, '/reports', '/out/app.apk')
    expect(outputs['AC_MOBSF_CRITICAL_COUNT']).to eq(1)
    expect(outputs['AC_MOBSF_NORMAL_COUNT']).to eq(2)
    expect(outputs['AC_MOBSF_LOW_COUNT']).to eq(3)
    expect(outputs['AC_MOBSF_FINDING_COUNT']).to eq(6)
    expect(outputs['AC_MOBSF_WORST_LEVEL']).to eq('critical')
  end

  it 'reports none as the worst level for a clean scan' do
    outputs = get_step_outputs(summarize_report(appsec_report), '/reports', '/a.apk')
    expect(outputs['AC_MOBSF_WORST_LEVEL']).to eq('none')
  end
end

# ─── 11. End to end ───────────────────────────────────────────────────────────
# Runs main.rb the way the runner does, against a stand-in mobsf-control.sh.
RSpec.describe 'main.rb end to end' do
  def with_apk
    Dir.mktmpdir do |dir|
      yield touch_artifact(dir, 'app-release.apk')
    end
  end

  context 'positive path – APK scanned' do
    it 'drives mobsf-control.sh, publishes the report and exports the outputs' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk }, { report: appsec_report(warning: 2, secure: 3, score: 67) }) do |result|
          expect(result[:success]).to be(true), "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
          expect(result[:scanned_file]).to eq(apk)
          expect(result[:mobsf_args]).to include('--action scan')
          expect(result[:mobsf_args]).to include('--scan-timeout 1800')

          expect(File.file?(File.join(result[:output_dir], 'mobsf-report.json'))).to be true
          expect(result[:outputs]['AC_MOBSF_SECURITY_SCORE']).to eq('67')
          expect(result[:outputs]['AC_MOBSF_NORMAL_COUNT']).to eq('2')
          expect(result[:outputs]['AC_MOBSF_WORST_LEVEL']).to eq('normal')
          expect(result[:outputs]['AC_MOBSF_SCANNED_ARTIFACT']).to eq(apk)
        end
      end
    end

    it 'prints the summary in the step form vocabulary and ends in a verdict' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk }, { report: appsec_report(high: 1, score: 30) }) do |result|
          expect(result[:stdout]).to include('Critical')
          expect(result[:stdout]).to include('Passed checks')
          expect(result[:stdout]).to include('Fail build on')
          expect(result[:stdout]).to include('Verdict')
          expect(result[:stdout]).not_to include('WARNING :')
        end
      end
    end
  end

  # MobSF converts an AAB to an APK with its own bundletool, so an AAB is a
  # supported artifact rather than an early failure.
  context 'positive path – AAB scanned' do
    it 'sends the AAB from AC_AAB_PATH' do
      Dir.mktmpdir do |dir|
        aab = touch_artifact(dir, 'app-release.aab')
        run_main({ 'AC_AAB_PATH' => aab }, { report: appsec_report(score: 90) }) do |result|
          expect(result[:success]).to be(true), "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
          expect(result[:scanned_file]).to eq(aab)
        end
      end
    end
  end

  context 'positive path – IPA discovered under the export directory' do
    it 'scans the ipa without an explicit path' do
      Dir.mktmpdir do |dir|
        ipa = touch_artifact(dir, 'Appcircle.ipa')
        run_main({ 'AC_EXPORT_DIR' => dir }, { report: appsec_report(score: 67) }) do |result|
          expect(result[:success]).to be(true), "step failed:\n#{result[:stdout]}\n#{result[:stderr]}"
          expect(result[:scanned_file]).to eq(ipa)
        end
      end
    end
  end

  context 'negative path – the gate breaks the pipeline' do
    it 'fails on a critical finding and still publishes the report' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'AC_MOBSF_FAIL_ON' => 'critical' },
                 { report: appsec_report(high: 1, score: 20) }) do |result|
          expect(result[:success]).to be false
          expect(result[:stdout] + result[:stderr]).to include('breaks the pipeline')
          expect(File.file?(File.join(result[:output_dir], 'mobsf-report.json'))).to be true
        end
      end
    end

    it 'fails on a score below the minimum' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'AC_MOBSF_FAIL_ON' => 'none', 'AC_MOBSF_MIN_SCORE' => '80' },
                 { report: appsec_report(score: 40) }) do |result|
          expect(result[:success]).to be false
          expect(result[:stdout] + result[:stderr]).to include('below the required 80')
        end
      end
    end

    it 'reports only when the gate is none and no score is set' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'AC_MOBSF_FAIL_ON' => 'none' },
                 { report: appsec_report(high: 5, score: 10) }) do |result|
          expect(result[:success]).to be true
          expect(result[:outputs]['AC_MOBSF_CRITICAL_COUNT']).to eq('5')
        end
      end
    end
  end

  # Binary analysis has no CLI fallback, so an unprovisioned runner is a
  # failure with the provisioning script named, not a silent degradation.
  context 'negative path – MobSF not provisioned' do
    it 'fails naming setup-mobsf.sh' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk }) do |result|
          expect(result[:success]).to be false
          expect(result[:stdout] + result[:stderr]).to include('setup-mobsf.sh')
          expect(result[:stdout] + result[:stderr]).to include('license does not allow it')
        end
      end
    end
  end

  context 'negative path – the scan itself fails' do
    it 'fails with the control script message' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk }, { exit_code: 1 }) do |result|
          expect(result[:success]).to be false
          expect(result[:stdout] + result[:stderr]).to include('The MobSF scan failed')
        end
      end
    end

    it 'names setup-mobsf.sh when the installation is incomplete' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk }, { exit_code: 3 }) do |result|
          expect(result[:success]).to be false
          expect(result[:stdout] + result[:stderr]).to include('setup-mobsf.sh --action status')
        end
      end
    end
  end

  context 'negative path – no artifact' do
    it 'fails naming the build steps it should follow' do
      run_main({}, { report: appsec_report }) do |result|
        expect(result[:success]).to be false
        expect(result[:stdout] + result[:stderr]).to include('Android Build')
      end
    end
  end
end

# ─── Runner ───────────────────────────────────────────────────────────────────
if __FILE__ == $PROGRAM_NAME
  RSpec.configure do |config|
    config.add_formatter ReadableFormatter
    config.color  = true
    config.order  = :defined
  end

  exit RSpec::Core::Runner.run(['--order', 'defined'])
end
