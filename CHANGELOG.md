# Changelog

## [0.1.0] - 2026-08-20

- refactor: rename pcm module to stagehand (puppetlabs-stagehand) (37db262)
- feat: extract trivy/openscap/patchbot; patchbot Package Updates + Windows Update (30824ed)
- fix(trivy): restore pinned, checksum-verified trivy install (CVE-2026-33634) (4ca6f5c)
- fix(02-04): add test-only puppet-binary overrides to trivy_scan.sh/openscap_scan.sh (safety prerequisite) (5203e93)
- test(02-04): add failing test for trivy_scan.sh leading-dash guard and JSON-on-fail contract (6cd6770)
- feat(02-04): trivy_scan.sh rejects leading-dash scan_path and embeds JSON on business-logic failure; trivy_scan.json marks ingest_token sensitive and input_method both (145386e)
- fix(patchbot,trivy,openscap,inspector): correct metadata.json/README to unified stagehand Forge author + puppet-stagehand org (SPLIT-01, D-16/D-17/D-18, supersedes D-02) (82cab6a)
