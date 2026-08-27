# Bootstrapped for stagehand-trivy (modulesync-style scaffold, adapted from
# puppet-soup_patching's Gemfile). This module ships Bolt tasks + a shell
# adapter only (no manifests), so the "product" under test is
# tasks/trivy_scan.{json,sh} and files/trivy-report.sh -- but it still rides
# the same voxpupuli-test/rspec toolchain as every other module in this org
# so CI, lint, and validate all behave identically across the fleet.

source ENV['GEM_SOURCE'] || 'https://rubygems.org'

group :test do
  gem 'puppet_metadata', '~> 6.1',  :require => false
  gem 'json_schemer', '~> 2.3',     :require => false
  gem 'bundler-audit', '~> 0.9',    :require => false
end

# voxpupuli-test is declared outside any single `group do` block, with an
# explicit :groups => [:test, :system_tests], so its group membership is
# unambiguous (a gem call's own :groups option sets its groups outright; it
# does not merge with an enclosing `group do` block). It needs to survive
# BOTH bundle-exclusion shapes the reusable voxpupuli/gha-puppet
# beaker.yml@v4 workflow uses (wired in via ci.yml's `puppet:` job):
# setup_matrix/unit run with BUNDLE_WITHOUT=development:system_tests:release
# (excludes :system_tests, keeps :test), while acceptance runs with
# BUNDLE_WITHOUT=development:test:release (excludes :test, keeps
# :system_tests). Bundler only excludes a gem if ALL of its groups are
# excluded, so a single-group placement is guaranteed to vanish under one of
# those two combinations. spec/spec_helper.rb unconditionally requires
# 'voxpupuli/test/spec_helper', and every spec/acceptance/*_spec.rb requires
# spec_helper, so the acceptance leg's `bundle exec rake beaker` (which runs
# spec/acceptance via rspec) needs voxpupuli-test present too, not just
# :test-group consumers like `rake validate lint`.
gem 'voxpupuli-test', '~> 14.0', :require => false, :groups => [:test, :system_tests]

group :development do
  gem 'guard-rake',               :require => false
  gem 'overcommit', '>= 0.39.1',  :require => false
end

group :system_tests do
  gem 'puppet_litmus', '~> 2.5', :require => false
  gem 'voxpupuli-acceptance', '~> 4.4',  :require => false
end

group :release do
  gem 'voxpupuli-release', '~> 5.3',  :require => false
end

gem 'rake', :require => false

# Explicit puppet/openvox pins so PUPPET_GEM_VERSION / OPENVOX_GEM_VERSION
# actually control what `bundle install` resolves -- voxpupuli-test itself
# only pulls puppet in transitively (via rspec-puppet), which is not
# specific enough to validate the puppet7/puppet8 vs openvox8/openvox9
# matrix this module now declares in metadata.json.
gem 'puppet',  ENV.fetch('PUPPET_GEM_VERSION', ['>= 7', '< 9']),  :require => false, :groups => [:test]
gem 'openvox', ENV.fetch('OPENVOX_GEM_VERSION', ['>= 8', '< 10']), :require => false, :groups => [:test]

# vim: syntax=ruby
