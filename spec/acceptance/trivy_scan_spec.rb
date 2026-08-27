# frozen_string_literal: true

require 'spec_helper'
require 'open3'
require 'json'
require 'tmpdir'
require 'fileutils'

# Target-native acceptance coverage for trivy::trivy_scan (04.1-04-PLAN.md
# Task 2). trivy is a task-only module for Linux targets -- there is no
# manifest/catalog to compile against a running node here, so "acceptance"
# means invoking the REAL tasks/trivy_scan.sh binary as a real subprocess
# (mirroring stagehand's spec/acceptance/platform_lock_spec.rb and
# patchbot's spec/acceptance/patch_spec.rb Open3.capture3 pattern), not a
# stubbed rspec-puppet catalog assertion. tasks/trivy_scan_test.sh already
# covers the full adversarial matrix (leading-dash rejection, every failure
# branch, JSON-special certname round-trip) via its own shell harness --
# this spec is deliberately narrower: it proves the success path, the
# primary business-logic failure path, and the argument-injection guard
# end-to-end through a real `sh` process, real jq, and stubbed
# trivy/curl/puppet binaries, parsed back through Ruby's JSON parser rather
# than shell string comparison, as independent evidence the two harnesses
# agree.
RSpec.describe 'trivy::trivy_scan (POSIX, target-native acceptance)' do
  let(:repo_root) { File.expand_path('../..', __dir__) }
  let(:task_sh) { File.join(repo_root, 'tasks', 'trivy_scan.sh') }
  # trivy_scan.sh resolves its bundled adapter at
  # "$PT__installdir/trivy/files/trivy-report.sh" -- the same Bolt
  # module-staging convention tasks/trivy_scan_test.sh's own harness
  # already relies on (PT__installdir points one directory ABOVE a
  # directory literally named "trivy"). This only works because this
  # checkout's directory is itself named "trivy"; mirrors that existing
  # constraint rather than inventing a new resolution scheme.
  let(:installdir) { File.dirname(repo_root) }

  before do
    skip "trivy_scan.sh's bundled adapter lookup requires this checkout to be named 'trivy'" \
      unless File.basename(repo_root) == 'trivy'
  end

  def with_stubs(work_dir, trivy_writes_report:, curl_post_succeeds: true, certname: 'node1.example.com')
    shim_dir = File.join(work_dir, 'shims')
    FileUtils.mkdir_p(shim_dir)

    fixture_report = File.join(work_dir, 'fixture-trivy-report.json')
    File.write(fixture_report, JSON.generate(
                                  'SchemaVersion' => 2,
                                  'Results' => [{ 'Target' => 'test-target', 'Vulnerabilities' => [] }],
                                ))

    puppet_stub = File.join(shim_dir, 'puppet-stub')
    File.write(puppet_stub, <<~SHIM)
      #!/bin/sh
      case "$*" in
        *"config print certname"*) printf '%s\\n' "#{certname}"; exit 0 ;;
        *) exit 1 ;;
      esac
    SHIM
    FileUtils.chmod(0o755, puppet_stub)

    trivy_stub = File.join(shim_dir, 'trivy')
    File.write(trivy_stub, <<~SHIM)
      #!/bin/sh
      out=""
      prev=""
      for a in "$@"; do
        if [ "$prev" = "-o" ]; then out="$a"; fi
        prev="$a"
      done
      #{trivy_writes_report ? %(cat "#{fixture_report}" > "$out") : ':'}
      exit 0
    SHIM
    FileUtils.chmod(0o755, trivy_stub)

    curl_stub = File.join(shim_dir, 'curl')
    File.write(curl_stub, <<~SHIM)
      #!/bin/sh
      is_post=0
      prev=""
      for a in "$@"; do
        if [ "$prev" = "-X" ] && [ "$a" = "POST" ]; then is_post=1; fi
        prev="$a"
      done
      if [ "$is_post" = "1" ]; then
        exit #{curl_post_succeeds ? 0 : 1}
      fi
      exit 1
    SHIM
    FileUtils.chmod(0o755, curl_stub)

    { shim_dir: shim_dir, puppet_stub: puppet_stub }
  end

  def run_task(env)
    Open3.capture3(env, 'sh', task_sh)
  end

  around do |example|
    Dir.mktmpdir('trivy-acceptance-') do |dir|
      @work_dir = dir
      example.run
    end
  end

  it 'runs the real trivy_scan.sh subprocess end-to-end and emits parseable success JSON' do
    real_jq_dir = File.dirname(`which jq`.strip)
    stubs = with_stubs(@work_dir, trivy_writes_report: true, curl_post_succeeds: true)

    stdout, stderr, status = run_task(
      'PATH' => "#{stubs[:shim_dir]}:#{real_jq_dir}:/usr/bin:/bin",
      'HOME' => ENV.fetch('HOME', @work_dir),
      'PT_console_url' => 'https://console.example.com',
      'PT_ingest_token' => 'test-token',
      'PT_scan_path' => '/',
      'PT_install' => 'false',
      'PT__installdir' => installdir,
      'TRIVY_SCAN_PUPPET_BIN' => stubs[:puppet_stub],
    )

    expect(status).to be_success, "trivy_scan.sh exited #{status.exitstatus}, stderr: #{stderr}"
    evidence = JSON.parse(stdout)
    expect(evidence).to eq('status' => 'scanned', 'scanner' => 'trivy', 'certname' => 'node1.example.com')
  end

  it 'runs the real trivy_scan.sh subprocess end-to-end and emits parseable error JSON when the console POST fails' do
    real_jq_dir = File.dirname(`which jq`.strip)
    stubs = with_stubs(@work_dir, trivy_writes_report: true, curl_post_succeeds: false)

    stdout, stderr, status = run_task(
      'PATH' => "#{stubs[:shim_dir]}:#{real_jq_dir}:/usr/bin:/bin",
      'HOME' => ENV.fetch('HOME', @work_dir),
      'PT_console_url' => 'https://console.example.com',
      'PT_ingest_token' => 'test-token',
      'PT_scan_path' => '/',
      'PT_install' => 'false',
      'PT__installdir' => installdir,
      'TRIVY_SCAN_PUPPET_BIN' => stubs[:puppet_stub],
    )

    # Business-logic failures embed JSON on stdout and exit 0 (AUDIT-04) --
    # only setup/argv-validation failures use a nonzero exit.
    expect(status).to be_success, "trivy_scan.sh exited #{status.exitstatus}, stderr: #{stderr}"
    evidence = JSON.parse(stdout)
    expect(evidence.fetch('status')).to eq('error')
    expect(evidence.fetch('error')).to eq('POST to console failed')
    expect(evidence.fetch('scanner')).to eq('trivy')
  end

  it 'rejects an argument-injection scan_path before ever invoking trivy' do
    real_jq_dir = File.dirname(`which jq`.strip)
    stubs = with_stubs(@work_dir, trivy_writes_report: true, curl_post_succeeds: true)

    stdout, stderr, status = run_task(
      'PATH' => "#{stubs[:shim_dir]}:#{real_jq_dir}:/usr/bin:/bin",
      'HOME' => ENV.fetch('HOME', @work_dir),
      'PT_console_url' => 'https://console.example.com',
      'PT_scan_path' => '--allow-listing',
      'PT__installdir' => installdir,
      'TRIVY_SCAN_PUPPET_BIN' => stubs[:puppet_stub],
    )

    expect(status).not_to be_success
    expect(stdout).to eq('')
    expect(stderr).to match(/scan_path must not start with '-'/)
  end
end
