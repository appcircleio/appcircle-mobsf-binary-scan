# ─── Coverage (must start before loading main.rb) ─────────────────────────────
unless defined?(Coverage) && Coverage.running?
  require 'coverage'
  Coverage.start
end

# ─── Dependencies ─────────────────────────────────────────────────────────────
require 'rspec'
require 'rspec/core/formatters/base_formatter'
require 'fileutils'
require 'json'
require 'open3'
require 'rbconfig'
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
def plant_fake_mobsf(workspace, report, exit_code, control_dir = nil)
  prefix = File.join(workspace, 'mobsf')
  FileUtils.mkdir_p(prefix)
  File.write(File.join(prefix, 'appcircle-mobsf-manifest.json'),
             JSON.dump({ 'schemaVersion' => 1, 'mobsfVersion' => '4.5.2',
                         'listenPort' => 8000, 'prefix' => prefix }))

  scripts = control_dir || File.join(workspace, 'scripts')
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
    /bin/cp "#{payload}" "$output"
    echo "[MobSF] AppSec summary written"
    exit 0
  SH
  FileUtils.chmod(0o755, control)

  return prefix
end

# ─── Subprocess Coverage ──────────────────────────────────────────────────────
# The end to end and ENV validation examples run main.rb in a child process, so
# the guarded top-level code only executes there. A small helper preloaded with
# `ruby -r` collects the child's line coverage of main.rb, and it is merged into
# the report printed at the end of the run.
COVERAGE_TMP = Dir.mktmpdir('mobsf_binary_scan_coverage')
at_exit { FileUtils.rm_rf(COVERAGE_TMP) }

CHILD_COVERAGE_HELPER = File.join(COVERAGE_TMP, 'child_coverage.rb')
File.write(CHILD_COVERAGE_HELPER, <<~'RUBY')
  require 'coverage'
  require 'json'
  Coverage.start

  at_exit do
    out = ENV['MOBSF_TEST_COVERAGE_OUT']
    if out && !out.empty?
      main = Coverage.result.select { |path, _| path.end_with?('/main.rb') }
      File.write(out, JSON.generate(main))
    end
  end
RUBY

$subprocess_coverage = nil

def merge_subprocess_coverage(path)
  return unless File.file?(path)

  JSON.parse(File.read(path)).each_value do |lines|
    $subprocess_coverage ||= Array.new(lines.size)
    lines.each_with_index do |count, i|
      next if count.nil?

      $subprocess_coverage[i] = $subprocess_coverage[i].to_i + count
    end
  end
end

# ─── Subprocess Helper ────────────────────────────────────────────────────────
# Pass nil as a value to unset that variable in the child, so the ambient
# environment cannot leak into a missing-variable example.
def run_main(env = {}, fake_mobsf = nil)
  Dir.mktmpdir do |workspace|
    step_temp = File.join(workspace, 'step_temp')
    output_dir = File.join(workspace, 'output')
    env_file = File.join(workspace, 'env_file')
    FileUtils.mkdir_p([step_temp, output_dir])
    FileUtils.touch(env_file)

    mobsf_env = {}
    if fake_mobsf
      # control_on_path: the control script lives only in a PATH directory, so
      # it is not found through the scripts/ directories next to the prefix.
      control_dir = fake_mobsf[:control_on_path] ? File.join(workspace, 'path_bin') : nil
      mobsf_env['MOBSF_HOME'] =
        plant_fake_mobsf(workspace, fake_mobsf[:report], fake_mobsf.fetch(:exit_code, 0), control_dir)
      mobsf_env['PATH'] = [control_dir, ENV['PATH']].join(File::PATH_SEPARATOR) if control_dir
    end

    coverage_out = File.join(workspace, 'coverage.json')
    clean_env = INPUT_KEYS.each_with_object({}) { |key, acc| acc[key] = nil }
                          .merge('AC_STEP_TEMP' => step_temp,
                                 'AC_TEMP_DIR' => step_temp,
                                 'AC_OUTPUT_DIR' => output_dir,
                                 'AC_ENV_FILE_PATH' => env_file,
                                 'MOBSF_TEST_COVERAGE_OUT' => coverage_out)
                          .merge(mobsf_env)
                          .merge(env)

    # The absolute Ruby path keeps the launch independent of the child's PATH.
    stdout_str, stderr_str, status =
      Open3.capture3(clean_env, RbConfig.ruby, '-r', CHILD_COVERAGE_HELPER, MAIN_RB)
    merge_subprocess_coverage(coverage_out)
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
      output_dir: output_dir,
      mobsf_args: File.file?(args) ? File.read(args).strip : nil,
      scanned_file: File.file?(received) ? File.read(received).strip : nil
    })
  end
end

# ─── Tests ────────────────────────────────────────────────────────────────────

# ─── 0. Loading main.rb as a library ──────────────────────────────────────────
RSpec.describe 'loading main.rb' do
  it 'does not run the step when required' do
    expect($step_temp).to be_nil
    expect(defined?($summary) ? $summary : nil).to be_nil
  end

  it 'exits 0 and prints nothing when required by another script' do
    stdout_str, stderr_str, status = Open3.capture3(
      { 'AC_STEP_TEMP' => nil, 'AC_TEMP_DIR' => nil },
      RbConfig.ruby, '-e', "require #{MAIN_RB.inspect}; puts defined?(run_scan)"
    )
    expect(status.success?).to be true
    expect(stdout_str.strip).to eq('method')
    expect(stderr_str).to be_empty
  end
end

# ─── 0a. env_has_key ──────────────────────────────────────────────────────────
RSpec.describe '#env_has_key' do
  before { ENV.delete('MOBSF_TEST_KEY') }
  after { ENV.delete('MOBSF_TEST_KEY') }

  context 'positive path' do
    it 'returns the value' do
      ENV['MOBSF_TEST_KEY'] = '/runner/output'
      expect(env_has_key('MOBSF_TEST_KEY')).to eq('/runner/output')
    end

    it 'keeps surrounding whitespace, unlike env_default' do
      ENV['MOBSF_TEST_KEY'] = '  value  '
      expect(env_has_key('MOBSF_TEST_KEY')).to eq('  value  ')
    end
  end

  context 'negative path' do
    it 'aborts naming the key when it is missing' do
      expect { env_has_key('MOBSF_TEST_KEY') }.to raise_error(SystemExit)
      expect(capture_abort { env_has_key('MOBSF_TEST_KEY') }).to include('Missing MOBSF_TEST_KEY.')
    end

    it 'aborts naming the key when it is empty' do
      ENV['MOBSF_TEST_KEY'] = ''
      expect(capture_abort { env_has_key('MOBSF_TEST_KEY') }).to include('Missing MOBSF_TEST_KEY.')
    end

    it 'raises TypeError for a nil key' do
      expect { env_has_key(nil) }.to raise_error(TypeError)
    end
  end
end

# ─── 0b. env_default ──────────────────────────────────────────────────────────
RSpec.describe '#env_default' do
  before { ENV.delete('MOBSF_TEST_KEY') }
  after { ENV.delete('MOBSF_TEST_KEY') }

  context 'positive path' do
    it 'returns the value' do
      ENV['MOBSF_TEST_KEY'] = 'low'
      expect(env_default('MOBSF_TEST_KEY', 'critical')).to eq('low')
    end

    it 'strips surrounding whitespace' do
      ENV['MOBSF_TEST_KEY'] = "  /out/app.apk \n"
      expect(env_default('MOBSF_TEST_KEY', nil)).to eq('/out/app.apk')
    end
  end

  context 'negative path' do
    it 'returns the default when the key is missing' do
      expect(env_default('MOBSF_TEST_KEY', 'critical')).to eq('critical')
    end

    it 'returns the default when the value is empty' do
      ENV['MOBSF_TEST_KEY'] = ''
      expect(env_default('MOBSF_TEST_KEY', 'critical')).to eq('critical')
    end

    it 'returns nil when the default is nil' do
      expect(env_default('MOBSF_TEST_KEY', nil)).to be_nil
    end

    it 'returns an empty string, not the default, for a whitespace-only value' do
      ENV['MOBSF_TEST_KEY'] = '   '
      expect(env_default('MOBSF_TEST_KEY', 'critical')).to eq('')
    end

    it 'raises TypeError for a nil key' do
      expect { env_default(nil, 'x') }.to raise_error(TypeError)
    end
  end
end

# ─── 0c. get_step_temp ────────────────────────────────────────────────────────
RSpec.describe '#get_step_temp' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'uses AC_STEP_TEMP' do
      ENV['AC_STEP_TEMP'] = '/runner/step_tmp'
      ENV['AC_TEMP_DIR'] = '/runner/tmp'
      expect(get_step_temp).to eq('/runner/step_tmp')
    end

    it 'falls back to a folder under AC_TEMP_DIR' do
      ENV['AC_TEMP_DIR'] = '/runner/tmp'
      expect(get_step_temp).to eq('/runner/tmp/appcircle_mobsf_binary_scan')
    end

    it 'falls back to AC_TEMP_DIR when AC_STEP_TEMP is empty' do
      ENV['AC_STEP_TEMP'] = ''
      ENV['AC_TEMP_DIR'] = '/runner/tmp'
      expect(get_step_temp).to eq('/runner/tmp/appcircle_mobsf_binary_scan')
    end
  end

  context 'negative path' do
    it 'aborts when both are missing' do
      expect { get_step_temp }.to raise_error(SystemExit)
      expect(capture_abort { get_step_temp }).to include('Missing AC_STEP_TEMP or AC_TEMP_DIR.')
    end

    it 'aborts when both are empty' do
      ENV['AC_STEP_TEMP'] = ''
      ENV['AC_TEMP_DIR'] = ''
      expect(capture_abort { get_step_temp }).to include('Missing AC_STEP_TEMP or AC_TEMP_DIR.')
    end
  end
end

# ─── 0d. abort_script ─────────────────────────────────────────────────────────
RSpec.describe '#abort_script' do
  it 'raises SystemExit with status 1' do
    original = $stderr
    $stderr = StringIO.new
    expect { abort_script('boom') }.to raise_error(SystemExit) { |e| expect(e.status).to eq(1) }
  ensure
    $stderr = original
  end

  it 'prefixes the message with the @@[error] log tag' do
    expect(capture_abort { abort_script('MobSF scan failed') }).to eq("@@[error] MobSF scan failed\n")
  end

  it 'accepts an exception and prints its message' do
    error = Errno::ENOENT.new('/missing/report.json')
    expect(capture_abort { abort_script(error) }).to include('@@[error] No such file or directory')
  end

  it 'still aborts on a nil message' do
    expect(capture_abort { abort_script(nil) }).to eq("@@[error] \n")
  end
end

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

    it 'accepts every supported level, trimmed' do
      %w[critical normal low none].each do |level|
        ENV['AC_MOBSF_FAIL_ON'] = " #{level.capitalize} "
        expect(get_fail_on).to eq(level)
      end
    end

    it 'falls back to critical when the input is empty' do
      ENV['AC_MOBSF_FAIL_ON'] = ''
      expect(get_fail_on).to eq('critical')
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

    it 'aborts on a value with a unit suffix instead of reading 15 seconds' do
      ENV['AC_MOBSF_SCAN_TIMEOUT'] = '15m'
      expect { get_scan_timeout }.to raise_error(SystemExit)
    end

    it 'aborts on exponent notation instead of reading 1 second' do
      ENV['AC_MOBSF_SCAN_TIMEOUT'] = '1e3'
      expect { get_scan_timeout }.to raise_error(SystemExit)
    end

    it 'aborts on a negative value and names it' do
      ENV['AC_MOBSF_SCAN_TIMEOUT'] = '-30'
      expect(capture_abort { get_scan_timeout }).to include('Invalid scan timeout `-30`')
    end

    it 'falls back to the default when the input is empty' do
      ENV['AC_MOBSF_SCAN_TIMEOUT'] = ''
      expect(get_scan_timeout).to eq(1800)
    end
  end
end

# ─── 2b. run_command ──────────────────────────────────────────────────────────
RSpec.describe '#run_command' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'returns stdout and a zero exit code' do
      stdout_str = nil
      exit_code = nil
      capture_stdout do
        stdout_str, _stderr_str, exit_code = run_command(%w[sh -c echo\ hello], true)
      end
      expect(stdout_str.strip).to eq('hello')
      expect(exit_code).to eq(0)
    end

    it 'captures output larger than the pipe buffer' do
      stdout_str = nil
      capture_stdout do
        stdout_str, = run_command(['sh', '-c', 'i=0; while [ $i -lt 20000 ]; do ' \
                                   'echo "line $i"; i=$((i+1)); done'], true, 60)
      end
      expect(stdout_str.lines.length).to eq(20_000)
      expect(stdout_str.lines.last.strip).to eq('line 19999')
    end
  end

  context 'negative path – timeout exceeded' do
    it 'terminates the command so a stuck scan cannot hang the build' do
      message = nil
      capture_stdout { message = capture_abort { run_command(%w[sleep 30], true, 1) } }
      expect(message).to include('exceeded the 1 second timeout')
    end

    it 'fires at the timeout rather than after the kill grace period' do
      elapsed = nil
      capture_stdout do
        capture_abort do
          started = monotonic_now()
          run_command(%w[sleep 30], true, 1)
        ensure
          elapsed = monotonic_now() - started
        end
      end
      expect(elapsed).to be < 2.5
    end

    it 'does not wait on a background process that outlived the command' do
      stdout_str = nil
      exit_code = nil
      elapsed = nil
      capture_stdout do
        started = monotonic_now()
        stdout_str, _stderr_str, exit_code = run_command(
          ['sh', '-c', 'sleep 30 & echo started'], true, 2)
        elapsed = monotonic_now() - started
      end
      expect(elapsed).to be < 5
      expect(stdout_str.strip).to eq('started')
      expect(exit_code).to eq(0)
    end

    it 'escalates to KILL when the command ignores TERM' do
      message = nil
      elapsed = nil
      capture_stdout do
        started = monotonic_now()
        message = capture_abort { run_command(['sh', '-c', 'trap "" TERM; sleep 30'], true, 1) }
        elapsed = monotonic_now() - started
      end
      expect(message).to include('exceeded the 1 second timeout')
      expect(elapsed).to be < 10
    end
  end
end

RSpec.describe '#run_command – exit codes and errors' do
  context 'positive path' do
    it 'logs the command shell-escaped with the @@[command] tag' do
      log = capture_stdout { run_command(['echo', 'My App.ipa'], true) }
      expect(log).to include('@@[command] echo My\\ App.ipa')
    end

    it 'passes the arguments as an array and starts a new process group' do
      allow(Open3).to receive(:popen3).and_call_original
      capture_stdout { run_command(['echo', 'a; rm -rf /'], true) }
      expect(Open3).to have_received(:popen3).with('echo', 'a; rm -rf /', pgroup: true)
    end

    it 'returns stderr and the exit code without aborting when skip_abort is true' do
      result = nil
      capture_stdout { result = run_command(['sh', '-c', 'echo partial; echo boom >&2; exit 4'], true) }
      expect(result).to eq(["partial\n", "boom\n", 4])
    end

    it 'returns stderr of a successful command without aborting' do
      result = nil
      capture_stdout { result = run_command(['sh', '-c', 'echo note >&2'], false) }
      expect(result).to eq(['', "note\n", 0])
    end
  end

  context 'negative path' do
    it 'aborts with stderr on a non-zero exit when skip_abort is false' do
      message = nil
      capture_stdout { message = capture_abort { run_command(['sh', '-c', 'echo boom >&2; exit 4'], false) } }
      expect(message).to eq("@@[error] boom\n")
    end

    it 'aborts when the executable does not exist' do
      message = nil
      capture_stdout { message = capture_abort { run_command(['/nonexistent/mobsf-control.sh'], false) } }
      expect(message).to include('/nonexistent/mobsf-control.sh was not found on this runner.')
    end

    it 'aborts when the process cannot be reaped and reports no exit code' do
      out_r, out_w = IO.pipe
      err_r, err_w = IO.pipe
      out_w.close
      err_w.close
      stdin = double('stdin', close: nil)
      wait_thr = double('wait_thr', pid: 999_999)
      allow(wait_thr).to receive(:join).with(nil).and_return(wait_thr)
      allow(wait_thr).to receive(:join).with(REAP_TIMEOUT).and_return(nil)
      allow(Open3).to receive(:popen3).and_return([stdin, out_r, err_r, wait_thr])

      message = nil
      capture_stdout { message = capture_abort { run_command(['/r/mobsf-control.sh'], true) } }
      expect(message).to include('`mobsf-control.sh` could not be terminated on this runner')
      expect(out_r).to be_closed
      expect(err_r).to be_closed
    end

    it 'raises on a nil command' do
      expect { capture_stdout { run_command(nil, true) } }.to raise_error(NoMethodError)
    end
  end
end

# ─── 2c. monotonic_now ────────────────────────────────────────────────────────
RSpec.describe '#monotonic_now' do
  it 'returns seconds as a Float' do
    expect(monotonic_now).to be_a(Float)
  end

  it 'never goes backwards and measures elapsed time' do
    first = monotonic_now
    sleep 0.05
    second = monotonic_now
    expect(second - first).to be >= 0.05
  end

  it 'reads the monotonic clock, not the wall clock' do
    allow(Time).to receive(:now).and_return(Time.at(0))
    expect(monotonic_now).to be > 0
  end
end

# ─── 2d. read_stream ──────────────────────────────────────────────────────────
RSpec.describe '#read_stream' do
  context 'positive path' do
    it 'returns a thread that appends every line to the buffer' do
      reader, writer = IO.pipe
      buffer = +''
      thread = read_stream(reader, buffer)
      expect(thread).to be_a(Thread)
      writer.write("one\ntwo\nlast without newline")
      writer.close
      thread.join(5)
      expect(buffer).to eq("one\ntwo\nlast without newline")
      reader.close
    end

    it 'leaves the buffer empty for a stream with no output' do
      reader, writer = IO.pipe
      writer.close
      buffer = +''
      read_stream(reader, buffer).join(5)
      expect(buffer).to eq('')
      reader.close
    end
  end

  context 'negative path' do
    it 'swallows IOError from a stream closed before reading' do
      reader, writer = IO.pipe
      reader.close
      writer.close
      thread = read_stream(reader, +'')
      expect { thread.join(5) }.not_to raise_error
      expect(thread.alive?).to be false
    end

    it 'swallows Errno::EBADF' do
      io = double('io')
      allow(io).to receive(:each_line).and_raise(Errno::EBADF)
      expect { read_stream(io, +'').join(5) }.not_to raise_error
    end

    it 'lets any other error surface when the thread is joined' do
      io = double('io')
      allow(io).to receive(:each_line).and_raise(RuntimeError, 'decode failure')
      previous = Thread.report_on_exception
      Thread.report_on_exception = false
      thread = read_stream(io, +'')
      expect { thread.join(5) }.to raise_error(RuntimeError, 'decode failure')
    ensure
      Thread.report_on_exception = previous
    end
  end
end

# ─── 2e. stop_readers ─────────────────────────────────────────────────────────
RSpec.describe '#stop_readers' do
  before do
    stub_const('READER_DRAIN_TIMEOUT', 0.2)
    stub_const('KILL_GRACE_TIMEOUT', 0.2)
  end

  context 'positive path' do
    it 'leaves the streams open when every reader has finished' do
      reader, writer = IO.pipe
      writer.close
      thread = read_stream(reader, +'')
      thread.join(5)
      stop_readers([thread], [reader])
      expect(reader).not_to be_closed
      reader.close
    end

    it 'handles an empty reader list' do
      expect { stop_readers([], []) }.not_to raise_error
    end
  end

  context 'negative path' do
    it 'closes the streams so a reader blocked on an inherited pipe is released' do
      reader, writer = IO.pipe
      thread = read_stream(reader, +'')
      started = monotonic_now
      stop_readers([thread], [reader])
      expect(monotonic_now - started).to be < 2
      expect(reader).to be_closed
      expect(thread.join(1)).not_to be_nil
      writer.close
    end

    it 'kills a reader that does not stop after its stream is closed' do
      stuck = Thread.new { sleep 30 }
      stream = StringIO.new
      stop_readers([stuck], [stream])
      stuck.join(1)
      expect(stuck.alive?).to be false
      expect(stream).to be_closed
    end
  end
end

# ─── 2f. kill_process_group ───────────────────────────────────────────────────
RSpec.describe '#kill_process_group' do
  before do
    stub_const('KILL_GRACE_TIMEOUT', 0.5)
    stub_const('KILL_POLL_INTERVAL', 0.05)
  end

  def spawn_group(*command)
    pid = Process.spawn(*command, pgroup: true, out: File::NULL, err: File::NULL)
    [pid, Process.detach(pid)]
  end

  context 'positive path' do
    it 'terminates the whole group with TERM' do
      pid, waiter = spawn_group('sleep', '30')
      kill_process_group(pid)
      expect(waiter.join(5).value.termsig).to eq(Signal.list['TERM'])
    end

    it 'stops after TERM once the group is gone' do
      sent = []
      allow(self).to receive(:signal_process_group) do |_pid, signal|
        sent << signal
        signal == 'TERM'
      end
      kill_process_group(4321)
      expect(sent).to eq(['TERM', 0])
    end
  end

  context 'negative path' do
    it 'escalates to KILL when the group ignores TERM' do
      pid, waiter = spawn_group('sh', '-c', 'trap "" TERM; sleep 30')
      sleep 0.2
      kill_process_group(pid)
      expect(waiter.join(5).value.termsig).to eq(Signal.list['KILL'])
    end

    it 'sends KILL only after the grace period' do
      sent = []
      allow(self).to receive(:signal_process_group) do |_pid, signal|
        sent << signal
        true
      end
      started = monotonic_now
      kill_process_group(4321)
      expect(monotonic_now - started).to be >= 0.5
      expect(sent.first).to eq('TERM')
      expect(sent.last).to eq('KILL')
      expect(sent.count('KILL')).to eq(1)
    end

    it 'does nothing more when the group is already gone' do
      sent = []
      allow(self).to receive(:signal_process_group) do |_pid, signal|
        sent << signal
        false
      end
      kill_process_group(4321)
      expect(sent).to eq(['TERM'])
    end
  end
end

# ─── 2g. signal_process_group ─────────────────────────────────────────────────
RSpec.describe '#signal_process_group' do
  context 'positive path' do
    it 'returns true for a live group' do
      pid = Process.spawn('sleep', '30', pgroup: true)
      waiter = Process.detach(pid)
      expect(signal_process_group(pid, 0)).to be true
      Process.kill('KILL', -pid)
      waiter.join(5)
    end

    it 'signals the group, not just the leader' do
      allow(Process).to receive(:kill).and_return(1)
      signal_process_group(1234, 'TERM')
      expect(Process).to have_received(:kill).with('TERM', -1234)
    end
  end

  context 'negative path' do
    it 'returns false when the group no longer exists' do
      pid = Process.spawn('true', pgroup: true)
      Process.wait(pid)
      expect(signal_process_group(pid, 0)).to be false
    end

    it 'returns false when the runner is not allowed to signal the group' do
      allow(Process).to receive(:kill).and_raise(Errno::EPERM)
      expect(signal_process_group(1234, 'TERM')).to be false
    end

    it 'raises on an unknown signal name' do
      pid = Process.spawn('sleep', '30', pgroup: true)
      waiter = Process.detach(pid)
      expect { signal_process_group(pid, 'NOPE') }.to raise_error(ArgumentError)
    ensure
      Process.kill('KILL', -pid)
      waiter.join(5)
    end
  end
end

# ─── 3. get_minimum_score ─────────────────────────────────────────────────────
RSpec.describe '#get_minimum_score' do
  before { reset_inputs }
  after { reset_inputs }

  context 'positive path' do
    it 'defaults to 0, so the score gate is off' do
      expect(get_minimum_score).to eq(0)
    end

    it 'accepts a score in range' do
      ENV['AC_MOBSF_MIN_SCORE'] = '45'
      expect(get_minimum_score).to eq(45)
    end

    it 'accepts 100 as the strictest gate' do
      ENV['AC_MOBSF_MIN_SCORE'] = '100'
      expect(get_minimum_score).to eq(100)
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

    it 'aborts on a fractional score' do
      ENV['AC_MOBSF_MIN_SCORE'] = '45.5'
      expect(capture_abort { get_minimum_score }).to include('between 0 and 100')
    end

    it 'aborts on exponent notation' do
      ENV['AC_MOBSF_MIN_SCORE'] = '1e2'
      expect(capture_abort { get_minimum_score }).to include('between 0 and 100')
    end

    it 'aborts on a negative score' do
      ENV['AC_MOBSF_MIN_SCORE'] = '-1'
      expect(capture_abort { get_minimum_score }).to include('Invalid minimum security score `-1`')
    end

    it 'falls back to 0 when the input is empty' do
      ENV['AC_MOBSF_MIN_SCORE'] = ''
      expect(get_minimum_score).to eq(0)
    end
  end
end

# ─── 4. get_artifact_path ─────────────────────────────────────────────────────
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

    it 'skips an AC_APK_PATH that does not exist and falls back to the next source' do
      Dir.mktmpdir do |dir|
        aab = touch_artifact(dir, 'app.aab')
        ENV['AC_APK_PATH'] = File.join(dir, 'gone.apk')
        ENV['AC_AAB_PATH'] = aab
        capture_stdout { expect(get_artifact_path).to eq(aab) }
      end
    end

    it 'treats an empty input as unset' do
      Dir.mktmpdir do |dir|
        apk = touch_artifact(dir, 'app.apk')
        ENV['AC_MOBSF_ARTIFACT_PATH'] = ''
        ENV['AC_APK_PATH'] = apk
        capture_stdout { expect(get_artifact_path).to eq(apk) }
      end
    end

    it 'skips an export directory that does not exist' do
      Dir.mktmpdir do |dir|
        ipa = touch_artifact(dir, 'App.ipa')
        ENV['AC_EXPORT_DIR'] = File.join(dir, 'missing')
        ENV['AC_OUTPUT_DIR'] = dir
        log = capture_stdout { expect(get_artifact_path).to eq(ipa) }
        expect(log).to include('under AC_OUTPUT_DIR')
      end
    end
  end
end

# ─── 4a. resolve_artifact ─────────────────────────────────────────────────────
RSpec.describe '#resolve_artifact' do
  context 'positive path' do
    it 'returns the expanded path of a supported file' do
      Dir.mktmpdir do |dir|
        touch_artifact(dir, 'app.apk')
        Dir.chdir(dir) { expect(resolve_artifact('app.apk', 'test')).to eq(File.join(Dir.pwd, 'app.apk')) }
      end
    end

    it 'accepts the extension in any case' do
      Dir.mktmpdir do |dir|
        ipa = touch_artifact(dir, 'App.IPA')
        expect(resolve_artifact(ipa, 'test')).to eq(ipa)
      end
    end

    it 'accepts .apk, .aab and .ipa' do
      Dir.mktmpdir do |dir|
        %w[a.apk b.aab c.ipa].each do |name|
          path = touch_artifact(dir, name)
          expect(resolve_artifact(path, 'test')).to eq(path)
        end
      end
    end

    it 'picks the artifact inside a directory' do
      Dir.mktmpdir do |dir|
        aab = touch_artifact(dir, 'app.aab')
        expect(resolve_artifact(dir, 'test')).to eq(aab)
      end
    end
  end

  context 'negative path' do
    it 'aborts naming the origin when the path does not exist' do
      message = capture_abort { resolve_artifact('/nope/app.apk', 'AC_APK_PATH') }
      expect(message).to include('The artifact from AC_APK_PATH does not exist: /nope/app.apk')
    end

    it 'aborts on an unsupported extension' do
      Dir.mktmpdir do |dir|
        zip = touch_artifact(dir, 'app.zip')
        expect(capture_abort { resolve_artifact(zip, 'test') }).to include('MobSF cannot scan `.zip` files')
      end
    end

    it 'aborts on a file with no extension' do
      Dir.mktmpdir do |dir|
        bare = touch_artifact(dir, 'app')
        expect(capture_abort { resolve_artifact(bare, 'test') }).to include('MobSF cannot scan `` files')
      end
    end

    it 'aborts on an empty directory' do
      Dir.mktmpdir do |dir|
        expect(capture_abort { resolve_artifact(dir, 'test') }).to include("No APK, AAB or IPA found in #{dir}")
      end
    end

    it 'raises TypeError on a nil path' do
      expect { resolve_artifact(nil, 'test') }.to raise_error(TypeError)
    end
  end
end

# ─── 4b. find_artifacts ───────────────────────────────────────────────────────
RSpec.describe '#find_artifacts' do
  context 'positive path' do
    it 'returns every supported artifact, sorted' do
      Dir.mktmpdir do |dir|
        ipa = touch_artifact(dir, 'c.ipa')
        apk = touch_artifact(dir, 'b.apk')
        aab = touch_artifact(dir, 'a.aab')
        expect(find_artifacts(dir)).to eq([aab, apk, ipa])
      end
    end

    it 'ignores other files' do
      Dir.mktmpdir do |dir|
        apk = touch_artifact(dir, 'app.apk')
        touch_artifact(dir, 'mapping.txt')
        touch_artifact(dir, 'app.apk.sha256')
        expect(find_artifacts(dir)).to eq([apk])
      end
    end
  end

  context 'negative path' do
    it 'returns an empty list for an empty directory' do
      Dir.mktmpdir { |dir| expect(find_artifacts(dir)).to eq([]) }
    end

    it 'returns an empty list for a directory that does not exist' do
      expect(find_artifacts('/nonexistent/output')).to eq([])
    end

    it 'does not look into sub-directories' do
      Dir.mktmpdir do |dir|
        touch_artifact(File.join(dir, 'release'), 'app.apk')
        expect(find_artifacts(dir)).to eq([])
      end
    end

    it 'misses artifacts when the directory name holds glob characters (current behaviour)' do
      Dir.mktmpdir do |root|
        dir = File.join(root, 'build[1]')
        touch_artifact(dir, 'app.apk')
        expect(find_artifacts(dir)).to eq([])
      end
    end
  end
end

# ─── 4c. pick_single_artifact ─────────────────────────────────────────────────
RSpec.describe '#pick_single_artifact' do
  context 'positive path' do
    it 'returns the only artifact without a warning' do
      log = capture_stdout { expect(pick_single_artifact(['/out/app.apk'], '/out')).to eq('/out/app.apk') }
      expect(log).to be_empty
    end

    it 'returns the first of several and lists them in a warning' do
      found = ['/out/a.apk', '/out/b.ipa', '/out/c.aab']
      log = capture_stdout { expect(pick_single_artifact(found, '/out')).to eq('/out/a.apk') }
      expect(log).to include('@@[warning] 3 artifacts found in /out, scanning the first one.')
      expect(log).to include('a.apk, b.ipa, c.aab')
    end
  end

  context 'negative path' do
    it 'aborts naming the directory when nothing was found' do
      expect(capture_abort { pick_single_artifact([], '/out') }).to include('No APK, AAB or IPA found in /out.')
    end

    it 'raises NoMethodError on a nil list' do
      expect { pick_single_artifact(nil, '/out') }.to raise_error(NoMethodError)
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

  it 'falls back to the default prefixes in order' do
    allow(File).to receive(:file?).and_call_original
    allow(File).to receive(:file?).with('/opt/appcircle/mobsf/appcircle-mobsf-manifest.json').and_return(true)
    expect(get_mobsf_prefix).to eq('/opt/appcircle/mobsf')

    allow(File).to receive(:file?).with('/usr/local/appcircle/mobsf/appcircle-mobsf-manifest.json').and_return(true)
    expect(get_mobsf_prefix).to eq('/usr/local/appcircle/mobsf')
  end

  it 'prefers MOBSF_HOME over the default prefixes' do
    Dir.mktmpdir do |prefix|
      File.write(File.join(prefix, 'appcircle-mobsf-manifest.json'), '{}')
      ENV['MOBSF_HOME'] = prefix
      allow(File).to receive(:file?).and_call_original
      allow(File).to receive(:file?).with('/usr/local/appcircle/mobsf/appcircle-mobsf-manifest.json').and_return(true)
      expect(get_mobsf_prefix).to eq(prefix)
    end
  end

  it 'ignores an empty MOBSF_HOME' do
    ENV['MOBSF_HOME'] = ''
    allow(File).to receive(:file?).and_call_original
    expect(get_mobsf_prefix).to be_nil
    expect(File).not_to have_received(:file?).with('/appcircle-mobsf-manifest.json')
  end

  it 'does not take a manifest that is a directory' do
    Dir.mktmpdir do |prefix|
      FileUtils.mkdir_p(File.join(prefix, 'appcircle-mobsf-manifest.json'))
      ENV['MOBSF_HOME'] = prefix
      expect(get_mobsf_prefix).to be_nil
    end
  end
end

# ─── 5a. read_mobsf_manifest ──────────────────────────────────────────────────
RSpec.describe '#read_mobsf_manifest' do
  context 'positive path' do
    it 'parses the manifest' do
      Dir.mktmpdir do |prefix|
        File.write(File.join(prefix, 'appcircle-mobsf-manifest.json'),
                   JSON.dump({ 'mobsfVersion' => '4.5.2', 'listenPort' => 8000 }))
        expect(read_mobsf_manifest(prefix)).to eq({ 'mobsfVersion' => '4.5.2', 'listenPort' => 8000 })
      end
    end
  end

  context 'negative path' do
    it 'warns and returns nil on invalid JSON' do
      Dir.mktmpdir do |prefix|
        File.write(File.join(prefix, 'appcircle-mobsf-manifest.json'), '{ not json')
        log = capture_stdout { expect(read_mobsf_manifest(prefix)).to be_nil }
        expect(log).to include("@@[warning] The MobSF manifest under #{prefix} could not be read")
      end
    end

    it 'warns and returns nil when the manifest is missing' do
      Dir.mktmpdir do |prefix|
        log = capture_stdout { expect(read_mobsf_manifest(prefix)).to be_nil }
        expect(log).to include('No such file or directory')
      end
    end

    it 'warns and returns nil on an empty file' do
      Dir.mktmpdir do |prefix|
        File.write(File.join(prefix, 'appcircle-mobsf-manifest.json'), '')
        log = capture_stdout { expect(read_mobsf_manifest(prefix)).to be_nil }
        expect(log).to include('@@[warning]')
      end
    end

    it 'lets an unexpected read error surface' do
      allow(File).to receive(:read).and_raise(Errno::EACCES)
      expect { read_mobsf_manifest('/opt/appcircle/mobsf') }.to raise_error(Errno::EACCES)
    end
  end
end

# ─── 5b. get_mobsf_control_candidates ─────────────────────────────────────────
RSpec.describe '#get_mobsf_control_candidates' do
  before { reset_inputs }
  after { reset_inputs }

  around do |example|
    saved = ENV['PATH']
    example.run
  ensure
    ENV['PATH'] = saved
  end

  context 'positive path' do
    it 'puts the script inside the prefix first' do
      ENV['PATH'] = ''
      expect(get_mobsf_control_candidates('/opt/appcircle/mobsf').first).to eq('/opt/appcircle/mobsf/mobsf-control.sh')
    end

    it 'searches scripts/ in every ancestor of the prefix' do
      ENV['PATH'] = ''
      candidates = get_mobsf_control_candidates('/opt/appcircle/mobsf')
      expect(candidates).to include('/opt/appcircle/mobsf/scripts/mobsf-control.sh',
                                    '/opt/appcircle/scripts/mobsf-control.sh',
                                    '/opt/scripts/mobsf-control.sh')
    end

    it 'joins the root ancestor as //scripts, which resolves to /scripts' do
      ENV['PATH'] = ''
      expect(get_mobsf_control_candidates('/opt/appcircle/mobsf')).to include('//scripts/mobsf-control.sh')
    end

    it 'searches the step temp and AC_TEMP_DIR ancestors' do
      ENV['PATH'] = ''
      $step_temp = '/runner/work/step_tmp'
      ENV['AC_TEMP_DIR'] = '/agent/tmp'
      candidates = get_mobsf_control_candidates('/p')
      expect(candidates).to include('/runner/scripts/mobsf-control.sh', '/agent/scripts/mobsf-control.sh')
    end

    it 'adds every PATH directory, skipping empty entries' do
      ENV['PATH'] = ['/usr/local/bin', '', '/opt/bin'].join(File::PATH_SEPARATOR)
      candidates = get_mobsf_control_candidates('/p')
      expect(candidates.last(2)).to eq(['/usr/local/bin/mobsf-control.sh', '/opt/bin/mobsf-control.sh'])
      expect(candidates).not_to include('/mobsf-control.sh')
    end

    it 'lists each location once' do
      ENV['PATH'] = ['/opt/bin', '/opt/bin'].join(File::PATH_SEPARATOR)
      $step_temp = '/p'
      candidates = get_mobsf_control_candidates('/p')
      expect(candidates).to eq(candidates.uniq)
      expect(candidates.count('/opt/bin/mobsf-control.sh')).to eq(1)
    end
  end

  context 'negative path' do
    it 'adds no PATH locations when PATH is missing' do
      ENV.delete('PATH')
      candidates = get_mobsf_control_candidates('/p')
      expect(candidates).to eq(['/p/mobsf-control.sh', '/p/scripts/mobsf-control.sh', '//scripts/mobsf-control.sh'])
    end

    it 'adds no PATH locations when PATH is empty' do
      ENV['PATH'] = ''
      expect(get_mobsf_control_candidates('/p').length).to eq(3)
    end

    it 'skips the step temp and AC_TEMP_DIR when they are unset' do
      ENV['PATH'] = ''
      $step_temp = nil
      expect(get_mobsf_control_candidates('/p')).to eq(['/p/mobsf-control.sh', '/p/scripts/mobsf-control.sh',
                                                       '//scripts/mobsf-control.sh'])
    end
  end
end

# ─── 5c. ancestor_directories ─────────────────────────────────────────────────
RSpec.describe '#ancestor_directories' do
  context 'positive path' do
    it 'walks up to the root' do
      expect(ancestor_directories('/a/b/c')).to eq(['/a/b/c', '/a/b', '/a', '/'])
    end

    it 'expands a relative path' do
      Dir.mktmpdir do |dir|
        Dir.chdir(dir) { expect(ancestor_directories('x').first).to eq(File.join(Dir.pwd, 'x')) }
      end
    end

    it 'normalises dot segments and trailing slashes' do
      expect(ancestor_directories('/a/b/../c/')).to eq(['/a/c', '/a', '/'])
    end

    it 'returns only the root for /' do
      expect(ancestor_directories('/')).to eq(['/'])
    end
  end

  context 'negative path' do
    it 'stops at the limit on a deep path' do
      deep = '/' + (1..20).map { |i| "d#{i}" }.join('/')
      result = ancestor_directories(deep)
      expect(result.length).to eq(12)
      expect(result.last).to eq('/' + (1..9).map { |i| "d#{i}" }.join('/'))
    end

    it 'honours a custom limit' do
      expect(ancestor_directories('/a/b/c', 2)).to eq(['/a/b/c', '/a/b'])
    end

    it 'returns nothing for a zero limit' do
      expect(ancestor_directories('/a/b/c', 0)).to eq([])
    end

    it 'raises TypeError on a nil path' do
      expect { ancestor_directories(nil) }.to raise_error(TypeError)
    end
  end
end

# ─── 5d. require_mobsf_installation ───────────────────────────────────────────
RSpec.describe '#require_mobsf_installation' do
  before { reset_inputs }
  after { reset_inputs }

  around do |example|
    saved = ENV['PATH']
    Dir.mktmpdir do |empty_bin|
      ENV['PATH'] = empty_bin
      example.run
    end
  ensure
    ENV['PATH'] = saved
  end

  def provision(root, manifest: JSON.dump({ 'mobsfVersion' => '4.5.2' }), control: true)
    prefix = File.join(root, 'mobsf')
    FileUtils.mkdir_p(prefix)
    File.write(File.join(prefix, 'appcircle-mobsf-manifest.json'), manifest)
    if control
      File.write(File.join(prefix, 'mobsf-control.sh'), "#!/bin/sh\n")
      FileUtils.chmod(0o755, File.join(prefix, 'mobsf-control.sh'))
    end
    ENV['MOBSF_HOME'] = prefix
    $step_temp = prefix
    prefix
  end

  context 'positive path' do
    it 'returns the prefix and the control script and logs the version' do
      Dir.mktmpdir do |root|
        prefix = provision(root)
        result = nil
        log = capture_stdout { result = require_mobsf_installation }
        expect(result).to eq([prefix, File.join(prefix, 'mobsf-control.sh')])
        expect(log).to include("Found MobSF 4.5.2 at #{prefix}")
      end
    end

    it 'continues with a warning when the manifest cannot be parsed' do
      Dir.mktmpdir do |root|
        prefix = provision(root, manifest: 'not json')
        result = nil
        log = capture_stdout { result = require_mobsf_installation }
        expect(result.first).to eq(prefix)
        expect(log).to include('@@[warning]')
        expect(log).not_to include('Found MobSF')
      end
    end
  end

  context 'negative path' do
    it 'aborts with provisioning instructions when MobSF is not installed' do
      allow(self).to receive(:get_mobsf_prefix).and_return(nil)
      message = capture_abort { require_mobsf_installation }
      expect(message).to include('No MobSF installation found on this runner')
      expect(message).to include('/usr/local/appcircle/mobsf, /opt/appcircle/mobsf')
      expect(message).to include('setup-mobsf.sh --prefix <path>')
    end

    it 'aborts naming the searched locations when the control script is missing' do
      Dir.mktmpdir do |root|
        prefix = provision(root, control: false)
        message = nil
        capture_stdout { message = capture_abort { require_mobsf_installation } }
        count = get_mobsf_control_candidates(prefix).length
        expect(message).to include("mobsf-control.sh was not found in the #{count} locations searched under #{prefix}")
        expect(message).to include('and PATH')
      end
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

  it 'composes the exact argument list, all strings' do
    command = get_scan_command('/c.sh', '/p', '/a.apk', '/r.json', 1800)
    expect(command).to eq(['/c.sh', '--action', 'scan', '--file', '/a.apk', '--prefix', '/p',
                           '--output', '/r.json', '--scan-timeout', '1800'])
    expect(command).to all(be_a(String).or(be_nil))
  end

  it 'keeps shell metacharacters inert, since run_command passes an array' do
    command = get_scan_command('/c.sh', '/p', '/out/$(reboot);.apk', '/r.json', 60)
    expect(command[4]).to eq('/out/$(reboot);.apk')
    expect(command.shelljoin).to include('\\$\\(reboot\\)\\;.apk')
  end

  context 'negative path – nil inputs' do
    it 'keeps nil paths in place and stringifies a nil timeout' do
      command = get_scan_command(nil, nil, nil, nil, nil)
      expect(command.length).to eq(11)
      expect(command[4]).to be_nil
      expect(command.last).to eq('')
    end
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

  it 'uses the generic message for any other exit code' do
    expect(get_scan_failure_message(137, 'Killed')).to eq("The MobSF scan failed.\nKilled")
  end

  it 'ignores stderr for the known exit codes' do
    expect(get_scan_failure_message(3, 'noise')).not_to include('noise')
    expect(get_scan_failure_message(2, 'noise')).not_to include('noise')
  end

  context 'negative path – missing details' do
    it 'still returns the generic message for a nil exit code and nil stderr' do
      expect(get_scan_failure_message(nil, nil)).to eq("The MobSF scan failed.\n")
    end

    it 'returns the generic message for empty stderr' do
      expect(get_scan_failure_message(1, '')).to eq("The MobSF scan failed.\n")
    end
  end
end

# ─── 7a. parse_report ─────────────────────────────────────────────────────────
RSpec.describe '#parse_report' do
  it 'parses a report file' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'r.json')
      File.write(path, JSON.dump(appsec_report(score: 50)))
      expect(parse_report(path)['appsec']['security_score']).to eq(50)
    end
  end

  it 'aborts when no report was produced' do
    expect(capture_abort { parse_report('/nope/r.json') }).to include('MobSF did not produce a report at /nope/r.json.')
  end

  it 'aborts when the report is not JSON' do
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'r.json')
      File.write(path, '<html>')
      expect(capture_abort { parse_report(path) }).to include("The MobSF report at #{path} could not be parsed")
    end
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
      expect(get_gate_failure(normal, 'critical', 0)).to be_nil
    end

    it 'passes low findings at the normal gate' do
      expect(get_gate_failure(low, 'normal', 0)).to be_nil
    end

    it 'passes everything at none' do
      expect(get_gate_failure(critical, 'none', 0)).to be_nil
    end

    it 'passes a clean report at every level' do
      FAIL_ON_LEVELS.each { |level| expect(get_gate_failure(clean, level, 0)).to be_nil }
    end

    it 'passes when the score meets the minimum' do
      expect(get_gate_failure(low, 'none', 90)).to be_nil
    end
  end

  context 'negative path – pipeline breaks' do
    it 'fails on a critical finding at the critical gate' do
      expect(get_gate_failure(critical, 'critical', 0)).to include('`critical` finding or worse')
    end

    it 'fails on a normal finding at the normal gate' do
      expect(get_gate_failure(normal, 'normal', 0)).to include('`normal` finding or worse')
    end

    it 'fails on a low finding at the low gate' do
      expect(get_gate_failure(low, 'low', 0)).to include('`low` finding or worse')
    end

    it 'fails on a score below the minimum even when the level gate is none' do
      expect(get_gate_failure(critical, 'none', 50)).to include('30 is below the required 50')
    end

    it 'aborts on an unknown level' do
      expect(capture_abort { get_gate_failure(clean, 'blocker', 0) }).to include('Unknown fail build on level `blocker`')
    end
  end
end

# ─── 9a. print_summary ────────────────────────────────────────────────────────
RSpec.describe '#print_summary' do
  it 'prints every line and the verdict' do
    summary = summarize_report(appsec_report(high: 1, secure: 2, hotspot: 3, score: 40, trackers: 4))
    log = capture_stdout { print_summary(summary, '/out/app.apk', 'critical', 50) }
    expect(log).to include('Artifact              app.apk')
    expect(log).to include('Security score        40 / 100')
    expect(log).to include('Trackers              4')
    expect(log).to include('Minimum score         50')
    expect(log).to include('Verdict               pipeline breaks')
  end

  it 'omits trackers when MobSF reports none and labels the report-only gate' do
    report = appsec_report(score: 90)
    report['appsec'].delete('total_trackers')
    log = capture_stdout { print_summary(summarize_report(report), '/a.ipa', 'none', 0) }
    expect(log).not_to include('Trackers')
    expect(log).to include('none (report only)')
    expect(log).to include('0 (no score gate)')
    expect(log).to include('Worst level found     none')
    expect(log).to include('pipeline continues')
  end
end

RSpec.describe '#get_minimum_score_label' do
  it 'labels 0 and nil as no score gate' do
    expect(get_minimum_score_label(0)).to eq('0 (no score gate)')
    expect(get_minimum_score_label(nil)).to eq('0 (no score gate)')
  end

  it 'prints any other score as is' do
    expect(get_minimum_score_label(70)).to eq('70')
  end
end

# ─── 9b. copy_report / write_environment_variables ────────────────────────────
RSpec.describe '#copy_report' do
  before { reset_inputs }
  after { reset_inputs }

  it 'copies the report into the output directory' do
    Dir.mktmpdir do |dir|
      $report_path = File.join(dir, 'mobsf-binary-analyze.json')
      File.write($report_path, '{}')
      $output_path = File.join(dir, 'out/nested')
      capture_stdout { expect(copy_report).to eq($output_path) }
      expect(File.read(File.join($output_path, 'mobsf-binary-analyze.json'))).to eq('{}')
    end
  end

  it 'warns and skips publishing when AC_OUTPUT_DIR is not set' do
    log = capture_stdout { expect(copy_report).to be_nil }
    expect(log).to include('AC_OUTPUT_DIR is not set')
  end

  it 'aborts when the report cannot be copied' do
    Dir.mktmpdir do |dir|
      $report_path = File.join(dir, 'missing.json')
      $output_path = dir
      message = nil
      capture_stdout { message = capture_abort { copy_report } }
      expect(message).to include('@@[error] No such file or directory')
    end
  end
end

RSpec.describe '#write_environment_variables' do
  before { reset_inputs }
  after { reset_inputs }

  it 'appends KEY=value lines' do
    Dir.mktmpdir do |dir|
      $env_file_path = File.join(dir, 'env')
      File.write($env_file_path, "EXISTING=1\n")
      write_environment_variables({ 'AC_MOBSF_SECURITY_SCORE' => 55, 'AC_MOBSF_WORST_LEVEL' => 'none' })
      expect(File.read($env_file_path)).to eq("EXISTING=1\nAC_MOBSF_SECURITY_SCORE=55\nAC_MOBSF_WORST_LEVEL=none\n")
    end
  end

  it 'warns and exports nothing when AC_ENV_FILE_PATH is not set' do
    log = capture_stdout { write_environment_variables({ 'A' => 1 }) }
    expect(log).to include('AC_ENV_FILE_PATH is not set')
  end

  it 'aborts when the env file cannot be written' do
    $env_file_path = '/nonexistent/dir/env'
    expect(capture_abort { write_environment_variables({ 'A' => 1 }) }).to include('@@[error] No such file or directory')
  end
end

# ─── 10. get_step_outputs ─────────────────────────────────────────────────────
RSpec.describe '#get_step_outputs' do
  let(:summary) { summarize_report(appsec_report(high: 1, warning: 2, info: 3, score: 55)) }

  it 'exports the artifact and the score' do
    outputs = get_step_outputs(summary, '/out/app.apk')
    expect(outputs['AC_MOBSF_SCANNED_ARTIFACT']).to eq('/out/app.apk')
    expect(outputs['AC_MOBSF_SECURITY_SCORE']).to eq(55)
  end

  it 'exports no report path' do
    expect(get_step_outputs(summary, '/out/app.apk').keys.grep(/REPORT_PATH/)).to be_empty
  end

  it 'exports the counts in the form vocabulary' do
    outputs = get_step_outputs(summary, '/out/app.apk')
    expect(outputs['AC_MOBSF_CRITICAL_COUNT']).to eq(1)
    expect(outputs['AC_MOBSF_NORMAL_COUNT']).to eq(2)
    expect(outputs['AC_MOBSF_LOW_COUNT']).to eq(3)
    expect(outputs['AC_MOBSF_FINDING_COUNT']).to eq(6)
    expect(outputs['AC_MOBSF_WORST_LEVEL']).to eq('critical')
  end

  it 'reports none as the worst level for a clean scan' do
    outputs = get_step_outputs(summarize_report(appsec_report), '/a.apk')
    expect(outputs['AC_MOBSF_WORST_LEVEL']).to eq('none')
  end
end

# ─── 11. End to end ───────────────────────────────────────────────────────────
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

          expect(File.file?(File.join(result[:output_dir], 'mobsf-binary-analyze.json'))).to be true
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
          expect(File.file?(File.join(result[:output_dir], 'mobsf-binary-analyze.json'))).to be true
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

    it 'fails on a finding while the score is above the minimum' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'AC_MOBSF_FAIL_ON' => 'critical', 'AC_MOBSF_MIN_SCORE' => '10' },
                 { report: appsec_report(high: 1, score: 90) }) do |result|
          expect(result[:success]).to be false
          expect(result[:stdout] + result[:stderr]).to include('`critical` finding or worse')
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

# ─── 12. ENV validation (subprocess) ──────────────────────────────────────────
RSpec.describe 'ENV validation' do
  def with_apk
    Dir.mktmpdir do |dir|
      yield touch_artifact(dir, 'app-release.apk')
    end
  end

  def log_of(result)
    result[:stdout] + result[:stderr]
  end

  let(:report) { { report: appsec_report(warning: 1, score: 80) } }

  context 'AC_STEP_TEMP and AC_TEMP_DIR' do
    it 'fails when both are missing' do
      run_main({ 'AC_STEP_TEMP' => nil, 'AC_TEMP_DIR' => nil }) do |result|
        expect(result[:success]).to be false
        expect(result[:stderr]).to include('Missing AC_STEP_TEMP or AC_TEMP_DIR.')
      end
    end

    it 'fails when both are empty' do
      run_main({ 'AC_STEP_TEMP' => '', 'AC_TEMP_DIR' => '' }) do |result|
        expect(result[:success]).to be false
        expect(result[:stderr]).to include('Missing AC_STEP_TEMP or AC_TEMP_DIR.')
      end
    end

    it 'writes the report under AC_TEMP_DIR when AC_STEP_TEMP is missing' do
      with_apk do |apk|
        run_main({ 'AC_STEP_TEMP' => nil, 'AC_APK_PATH' => apk }, report) do |result|
          expect(result[:success]).to be(true), log_of(result)
          expected = File.join(result[:workspace], 'step_temp/appcircle_mobsf_binary_scan/mobsf-binary-analyze.json')
          expect(result[:mobsf_args]).to include("--output #{expected}")
        end
      end
    end
  end

  context 'AC_OUTPUT_DIR' do
    it 'publishes the report when set' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk }, report) do |result|
          expect(result[:success]).to be(true), log_of(result)
          expect(result[:stdout]).to include("Publishing mobsf-binary-analyze.json to #{result[:output_dir]}")
        end
      end
    end

    it 'warns and still succeeds when missing, without publishing the report' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'AC_OUTPUT_DIR' => nil }, report) do |result|
          expect(result[:success]).to be(true), log_of(result)
          expect(result[:stdout]).to include('@@[warning] AC_OUTPUT_DIR is not set, the report is not published')
          expect(Dir.children(result[:output_dir])).to be_empty
          expect(result[:outputs]['AC_MOBSF_SECURITY_SCORE']).to eq('80')
        end
      end
    end

    it 'fails with a non-zero exit when empty' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'AC_OUTPUT_DIR' => '' }, report) do |result|
          expect(result[:success]).to be false
          expect(result[:stderr]).to match(/@@\[error\] No such file or directory/)
          expect(result[:outputs]).to be_empty
        end
      end
    end

    it 'does not publish when AC_MOBSF_SAVE_REPORT is false' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'AC_MOBSF_SAVE_REPORT' => 'false' }, report) do |result|
          expect(result[:success]).to be(true), log_of(result)
          expect(Dir.children(result[:output_dir])).to be_empty
        end
      end
    end
  end

  context 'AC_ENV_FILE_PATH' do
    it 'exports the step outputs when set' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk }, report) do |result|
          expect(result[:success]).to be(true), log_of(result)
          expect(result[:outputs].keys).to include('AC_MOBSF_SCANNED_ARTIFACT', 'AC_MOBSF_WORST_LEVEL')
        end
      end
    end

    it 'warns and still succeeds when missing, without exporting outputs' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'AC_ENV_FILE_PATH' => nil }, report) do |result|
          expect(result[:success]).to be(true), log_of(result)
          expect(result[:stdout]).to include('@@[warning] AC_ENV_FILE_PATH is not set, the step outputs are not exported.')
          expect(result[:outputs]).to be_empty
        end
      end
    end

    it 'fails with a non-zero exit when empty' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'AC_ENV_FILE_PATH' => '' }, report) do |result|
          expect(result[:success]).to be false
          expect(result[:stderr]).to match(/@@\[error\] No such file or directory/)
        end
      end
    end

    it 'fails with a non-zero exit when its directory does not exist' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'AC_ENV_FILE_PATH' => '/nonexistent/dir/env' }, report) do |result|
          expect(result[:success]).to be false
          expect(result[:stderr]).to include('/nonexistent/dir/env')
        end
      end
    end
  end

  context 'PATH' do
    let(:on_path) { report.merge(control_on_path: true) }

    it 'finds mobsf-control.sh through PATH' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk }, on_path) do |result|
          expect(result[:success]).to be(true), log_of(result)
          expect(result[:stdout]).to include("@@[command] #{File.join(result[:workspace], 'path_bin/mobsf-control.sh')}")
        end
      end
    end

    it 'fails naming PATH when PATH is missing' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'PATH' => nil }, on_path) do |result|
          expect(result[:success]).to be false
          expect(result[:stderr]).to match(/mobsf-control\.sh was not found in the \d+ locations searched/)
          expect(result[:stderr]).to include('and PATH')
        end
      end
    end

    it 'fails naming PATH when PATH is empty' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'PATH' => '' }, on_path) do |result|
          expect(result[:success]).to be false
          expect(result[:stderr]).to match(/mobsf-control\.sh was not found in the \d+ locations searched/)
        end
      end
    end

    it 'does not need PATH when the script sits next to the installation' do
      with_apk do |apk|
        run_main({ 'AC_APK_PATH' => apk, 'PATH' => nil }, report) do |result|
          expect(result[:success]).to be(true), log_of(result)
        end
      end
    end
  end
end

# ─── Coverage Report ──────────────────────────────────────────────────────────
def print_coverage_report
  return unless defined?(Coverage) && Coverage.running?

  result = begin
    Coverage.result(stop: false, clear: false)
  rescue ArgumentError
    Coverage.result
  end

  data = result[MAIN_RB] || result[File.realpath(MAIN_RB)]
  return puts("\nCoverage: main.rb not found in results") unless data

  if $subprocess_coverage
    data = data.each_with_index.map do |count, i|
      count.nil? ? nil : count + $subprocess_coverage[i].to_i
    end
  end

  lines     = data.each_with_index.reject { |c, _| c.nil? }
  total     = lines.size
  covered   = lines.count { |c, _| c.to_i > 0 }
  pct       = total.positive? ? (covered * 100.0 / total).round(1) : 100.0
  uncovered = lines.select { |c, _| c.to_i == 0 }.map { |_, i| i + 1 }

  color = pct == 100 ? "\e[32;1m" : pct >= 80 ? "\e[33m" : "\e[31m"
  bar_filled = (pct / 5).round
  bar = "\e[32m" + '█' * bar_filled + "\e[90m" + '░' * (20 - bar_filled) + "\e[0m"

  puts "\n\e[90m#{'═' * 72}\e[0m"
  puts '  Coverage Report'
  puts "\e[90m#{'─' * 72}\e[0m"
  puts "  main.rb  #{bar}  #{color}#{pct}%\e[0m  (#{covered}/#{total} lines)"
  if uncovered.any? && uncovered.size <= 20
    puts "  Uncovered lines: \e[90m#{uncovered.join(', ')}\e[0m"
  elsif uncovered.any?
    puts "  Uncovered lines: \e[90m#{uncovered.first(15).join(', ')} … (+#{uncovered.size - 15} more)\e[0m"
  end
  puts "\e[90m#{'═' * 72}\e[0m"
end

# ─── Runner ───────────────────────────────────────────────────────────────────
if __FILE__ == $PROGRAM_NAME
  RSpec.configure do |config|
    config.add_formatter ReadableFormatter
    config.color  = true
    config.order  = :defined
  end

  exit_code = RSpec::Core::Runner.run(['--order', 'defined'])
  print_coverage_report
  exit exit_code
end
