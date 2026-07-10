# Static analysis

`KSword.Sandbox.Core.StaticAnalysis.StaticAnalyzer` performs bounded,
host-side triage before a sample is executed in a VM. It does not require
external tools and intentionally writes findings into the stable
`StaticAnalysisResult` contract:

- `Tags`: rule-facing tokens consumed by `rules/behavior-rules.json`.
- `Urls`: bounded URL strings extracted from ASCII/UTF-16 strings.
- `InterestingStrings`: bounded human-readable evidence such as imports,
  exports, resources, paths, IPs, and command strings.
- `Warnings`: parse-boundary and truncation notes.

## PE coverage

The analyzer parses these PE structures best-effort with hard limits:

- DOS/PE headers, architecture, subsystem, entry point, and section count.
- Section names, raw sizes, virtual sizes, entropy, and characteristics.
- Imports by module/API, including ordinal fallback evidence.
- Exports and registration/service-style entry points.
- TLS directory and callback-table pointers.
- Resource directory types and resource data entries.

Resource tags include `resources_present`, `resource_type_rcdata`,
`resource_manifest`, `resource_version_info`, `resource_icon`,
`resource_payload_candidate`, `resource_large_data`,
`resource_high_entropy_data`, and `resource_embedded_pe`.

Section tags include `high_entropy_section`, `very_high_entropy_section`,
`low_entropy_section`, `virtual_only_section`, `oversized_virtual_section`,
`executable_section`, `writable_section`, and
`writable_executable_section`.

## String and indicator coverage

String scanning is capped at 32 MiB and extracts printable ASCII plus simple
UTF-16LE strings. Current labels include:

- URLs and network indicators: `url`, `embedded_url`, `ip_address`,
  `public_ip_address`, `private_or_reserved_ip_address`.
- Paths: `windows_path_string`, `file_path_string`, `temp_path_string`,
  `appdata_path_string`, `registry_path_string`,
  `run_key_path_string`, `service_registry_path_string`,
  `startup_folder_path_string`, `environment_path_string`.
- Execution strings: `script_execution_string`, `powershell_string`,
  `encoded_command_string`, `lolbin_string`.
- Anti-analysis strings: `anti_analysis_string`,
  `sandbox_evasion_string`, `debugger_evasion_string`.
- Packer strings: `packer_string_hint`.

## Import/API grouping

Import and fallback API-string tags are grouped to keep rules concise:

- Injection: `import_process_injection_api`
- Dynamic code: `import_dynamic_code_api`
- Network/download: `import_network_api`, `import_network_library`
- Persistence: `import_persistence_api`,
  `import_registry_persistence_api`, `import_service_persistence_api`
- File drop/release: `import_file_drop_api`
- Script/process launch: `import_script_execution_api`
- Resource extraction: `import_resource_api`
- Anti-analysis: `import_anti_analysis_api`

All grouped API hits also set `import_suspicious_api` for broad triage.

## Rule integration

`SandboxJobService` emits `static.analysis.completed` with
`Data["tags"]` set to a comma-joined copy of `StaticAnalysisResult.Tags`.
Rules under `rules/behavior-rules.json` use `dataContains.tags` predicates to
map static tags to MITRE techniques without changing public report models.

The smoke scenario
`tests/KSword.Sandbox.SmokeTests/Scenarios/StaticRulesMitreScenario.cs`
validates that:

1. Static and dynamic behavior rules load.
2. Rule-referenced MITRE IDs exist in `rules/mitre-windows-map.json`.
3. Synthetic static tags classify into expected findings.
4. Synthetic files produce URL/IP/path/script/anti-analysis/resource tags.
