begin
  require 'voxpupuli/test/rake'
rescue LoadError
  # only available if gem group test is installed
end

begin
  require 'voxpupuli/acceptance/rake'
rescue LoadError
  # only available if gem group acceptance is installed
end

begin
  require 'puppet_litmus/rake_tasks'
rescue LoadError
  # only available if the system_tests bundle is installed
end

require 'fileutils'
task :spec_prep do
  FileUtils.mkdir_p('spec/fixtures')
end

begin
  require 'voxpupuli/release/rake_tasks'
rescue LoadError
  # only available if gem group releases is installed
else
  GCGConfig.user = 'puppet-stagehand'
  GCGConfig.project = 'trivy'
end

desc 'Run the hand-written Bolt task shell-test harnesses under tasks/*_test.sh'
task :shelltest do
  Dir.glob('tasks/*_test.sh').sort.each do |script|
    puts ">>> running #{script}"
    ok = system('/bin/sh', script)
    raise "#{script} failed" unless ok
  end
end

desc 'Run bundler-audit against the Gemfile.lock dependency set'
task :bundle_audit do
  sh 'bundle exec bundle-audit check --update'
end

# vim: syntax=ruby
