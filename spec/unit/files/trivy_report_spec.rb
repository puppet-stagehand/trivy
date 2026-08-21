# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'open3'
require 'tempfile'

# files/trivy-report.sh is the adapter that turns a real `trivy` JSON report
# into the compliance.v1 batch this module's task POSTs to the console. It
# has no prior test coverage; these specs actually execute it (it only needs
# bash + jq, both safe to run locally/in CI) against fixture Trivy reports
# and assert on the real output, not just static source inspection.
RSpec.describe 'the trivy-report.sh adapter' do
  let(:module_root) { File.expand_path('../../..', __dir__) }
  let(:adapter) { File.join(module_root, 'files', 'trivy-report.sh') }

  def run_adapter(report_hash, certname: 'node1.example.com')
    Tempfile.create(['trivy-report', '.json']) do |f|
      f.write(JSON.generate(report_hash))
      f.flush
      stdout, stderr, status = Open3.capture3('bash', adapter, '--report', f.path, '--certname', certname)
      [stdout, stderr, status]
    end
  end

  before do
    skip 'jq is required to exercise the real adapter' unless system('command -v jq >/dev/null 2>&1')
  end

  it 'normalizes a vulnerability finding into a compliance.v1 result' do
    report = {
      'SchemaVersion' => 2,
      'Results' => [
        {
          'Target' => 'app/package-lock.json',
          'Vulnerabilities' => [
            {
              'VulnerabilityID' => 'CVE-2024-12345',
              'Severity' => 'HIGH',
              'PkgName' => 'lodash',
              'InstalledVersion' => '4.17.15',
              'FixedVersion' => '4.17.21',
              'Title' => 'prototype pollution',
            },
          ],
        },
      ],
    }

    stdout, stderr, status = run_adapter(report)
    expect(status).to be_success, stderr
    batch = JSON.parse(stdout)

    expect(batch['schema_version']).to eq('compliance.v1')
    expect(batch.dig('source', 'scanner')).to eq('trivy')

    result = batch.fetch('results').first
    expect(result['node']).to eq('node1.example.com')
    expect(result['benchmark_id']).to eq('trivy-vuln:app/package-lock.json')
    expect(result['control_id']).to eq('CVE-2024-12345')
    expect(result['status']).to eq('fail')
    expect(result['severity']).to eq('high')
    expect(result['remediation_ref']).to eq('fixed in 4.17.21')
  end

  it 'maps misconfiguration PASS/FAIL/other statuses directly instead of forcing everything to fail' do
    report = {
      'SchemaVersion' => 2,
      'Results' => [
        {
          'Target' => 'Dockerfile',
          'Misconfigurations' => [
            { 'ID' => 'AVD-DS-0001', 'Severity' => 'MEDIUM', 'Status' => 'FAIL', 'Title' => 'root user' },
            { 'ID' => 'AVD-DS-0002', 'Severity' => 'LOW', 'Status' => 'PASS', 'Title' => 'healthcheck present' },
          ],
        },
      ],
    }

    stdout, stderr, status = run_adapter(report)
    expect(status).to be_success, stderr
    results = JSON.parse(stdout).fetch('results')

    fail_result = results.find { |r| r['control_id'] == 'AVD-DS-0001' }
    pass_result = results.find { |r| r['control_id'] == 'AVD-DS-0002' }
    expect(fail_result['status']).to eq('fail')
    expect(fail_result['severity']).to eq('medium')
    expect(pass_result['status']).to eq('pass')
    expect(pass_result['severity']).to eq('low')
  end

  it 'emits a single synthetic pass result for a clean scan so the ingest endpoint never sees an empty batch' do
    report = { 'SchemaVersion' => 2, 'Results' => [{ 'Target' => 'app', 'Vulnerabilities' => [] }] }

    stdout, stderr, status = run_adapter(report)
    expect(status).to be_success, stderr
    results = JSON.parse(stdout).fetch('results')

    expect(results.length).to eq(1)
    expect(results.first['status']).to eq('pass')
    expect(results.first['control_id']).to eq('no-findings')
  end

  it 'fails loudly (non-zero exit) when --report is missing or unreadable' do
    _stdout, _stderr, status = Open3.capture3('bash', adapter, '--report', '/nonexistent/path.json')
    expect(status).not_to be_success
  end
end
