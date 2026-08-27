# frozen_string_literal: true

require 'spec_helper'
require 'json'

# This module has no manifests (it is a Bolt-task-only module: the "product"
# is tasks/trivy_scan.{json,sh} + files/trivy-report.sh), so there is no
# class/define catalog to compile. These specs are the equivalent contract
# check for a task-only module: task metadata is well-formed and matches
# what trivy_scan.sh actually implements, and the pinned-version+checksum
# install pattern (CVE-2026-33634 fix) is present and has not regressed.
RSpec.describe 'the trivy::trivy_scan task' do
  let(:module_root) { File.expand_path('../../..', __dir__) }
  let(:task_json_path) { File.join(module_root, 'tasks', 'trivy_scan.json') }
  let(:task_sh_path) { File.join(module_root, 'tasks', 'trivy_scan.sh') }
  let(:metadata) { JSON.parse(File.read(task_json_path)) }
  let(:source) { File.read(task_sh_path) }

  it 'declares exactly the four documented parameters with the expected types' do
    params = metadata.fetch('parameters')
    expect(params.keys).to contain_exactly('console_url', 'ingest_token', 'scan_path', 'install')

    expect(params.dig('console_url', 'type')).to eq('String[1]')
    expect(params.dig('ingest_token', 'type')).to eq('Optional[String[1]]')
    expect(params.dig('ingest_token', 'sensitive')).to be(true)
    expect(params.dig('scan_path', 'type')).to include('Pattern')
    expect(params.dig('scan_path', 'default')).to eq('/')
    expect(params.dig('install', 'type')).to eq('Boolean')
    expect(params.dig('install', 'default')).to be(false)
  end

  it 'is self-contained: bundles the trivy-report adapter and accepts both param styles' do
    expect(metadata.fetch('files')).to include('trivy/files/trivy-report.sh')
    expect(metadata.fetch('input_method')).to eq('both')
  end

  it 'rejects a leading-dash scan_path before it ever reaches the trivy argv (D-05 input-validation gate)' do
    expect(source).to match(%r{case\s+"\$SCAN_PATH"\s+in})
    expect(source).to match(%r{-\*\)\s+die})
  end

  it 'pins the Trivy release and verifies its checksum before install (CVE-2026-33634 fix — never regress to curl\|sh)' do
    expect(source).to match(%r{TRIVY_VERSION="0\.72\.0"})
    expect(source).not_to match(%r{curl[^\n]*\|\s*sh\b})
    expect(source).to match(%r{sha256sum})
    expect(source).to match(%r{EXPECTED.*=.*ACTUAL|ACTUAL.*=.*EXPECTED|\[\s*"\$EXPECTED"\s*=\s*"\$ACTUAL"\s*\]})
  end

  it 'never installs trivy automatically unless install=true is explicitly requested' do
    expect(source).to match(%r{if\s+\[\s*"\$INSTALL"\s*=\s*"true"\s*\]})
  end

  it 'embeds business-logic failures as {"status":"error",...} JSON on stdout with exit 0 (not a bare non-zero exit), safely encoded via jq' do
    fail_json_body = source[%r{^fail_json\(\)\s*\{.*?^\}}m]
    expect(fail_json_body).not_to be_nil
    expect(fail_json_body).to include('status: "error"').and include('scanner: "trivy"').and include('exit 0')
    expect(fail_json_body).to match(%r{jq\s+-cn\s+--arg\s+error\s+"\$\*"}), 'expected fail_json to use jq -cn --arg (safe encoding), not hand-rolled printf/string interpolation'
  end

  it 'requires console_url and dies (setup failure, non-zero exit) when it is missing' do
    expect(source).to match(%r{\[\s*-n\s*"\$CONSOLE"\s*\]\s*\|\|\s*die\s*"console_url is required"})
  end
end
