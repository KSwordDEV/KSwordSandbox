# Static analysis

Canonical scope: this page owns the host-side analyzer contract. Rule-author
tag vocabulary notes live in `rules/static-analysis-notes.md`, and full rule
coverage/counts live in `docs/behavior-rule-matrix.md`.

Static analysis may inspect local executable samples, but samples and generated
analysis/report artifacts must stay under the runtime root or another ignored
lab path. Do not commit samples, `bin/`, `obj/`, native build outputs, reports,
or imported runtime events.

`KSword.Sandbox.Core.StaticAnalysis.StaticAnalyzer` performs bounded,
host-side triage before a sample is executed in a VM. It does not require
external tools and intentionally writes findings into the stable
`StaticAnalysisResult` contract:

- `Tags`: rule-facing tokens consumed by `rules/behavior-rules.json`.
- `Urls`: bounded URL strings extracted from ASCII/UTF-16 strings.
- `InterestingStrings`: bounded human-readable evidence such as imports,
  exports, section summaries, resources, overlay/signature hints, paths, URLs,
  IPs, debug/PDB metadata, version/manifest metadata, and command strings.
- `Imports`: structured import modules with bounded API names, ordinal import
  samples, suspicious API names, and per-module suspicious cluster names.
- `ImportApiClusters`: structured rollups such as `process-injection`,
  `dynamic-code`, `network`, `download`, `exfiltration`,
  `registry-persistence`, `credential-access`, `defense-evasion`, and
  `script-execution` with hit counts and API samples.
- `ExportModuleName` and `ExportNames`: bounded export-table names suitable for
  report JSON grouping and future rule predicates.
- `Tls`: TLS directory, callback-table VA/file offset, and callback
  VA/RVA/target-file-offset evidence.
- `Overlay`: PE overlay offset/size, certificate-table overlap,
  non-certificate appended size, and bounded entropy.
- `NetworkIndicators`: structured URL, domain, IPv4, and email indicators with
  coarse classification (`embedded`, `reference`, `public`,
  `private_or_reserved`, `dynamic_dns`, `onion`).
- `PathIndicators`: structured registry, filesystem, and environment-path
  indicators with the same stable tag vocabulary used by rules.
- `CommandIndicators`: structured script interpreter, encoded command, LOLBIN,
  download, and upload/exfil command-string evidence.
- `SuspiciousStrings`: structured anti-analysis, packer, persistence,
  credential-access, defense-evasion, and suspicious API-like string findings.
- `Warnings`: parse-boundary and truncation notes.

## PE coverage

The analyzer parses these PE structures best-effort with hard limits:

- DOS/PE headers, architecture, subsystem, entry point, and section count.
- Section names, raw offsets, raw sizes, virtual sizes, entropy,
  coarse entropy labels, characteristics, and executable/writable flags.
- Copyable section evidence strings in the form
  `section:<name>,va=<rva>,vsize=<n>,raw=<n>,entropy=<n>` for report grouping.
- Imports by module/API, including ordinal fallback evidence.
- Import-table aggregate evidence in the form
  `import-summary:modules=<n>,namedApis=<n>,ordinals=<n>`,
  `import-module:<dll>,namedApis=<n>,ordinals=<n>`, and suspicious API
  cluster rollups such as `import-api-cluster:process-injection,hits=<n>`.
  The same data is also exposed in `Imports` and `ImportApiClusters`.
- Exports and registration/service-style entry points.
  Parsed names are also exposed in `ExportModuleName` and `ExportNames`.
- PE security directory / Authenticode certificate table presence and bounded
  WIN_CERTIFICATE entry metadata.
- TLS directory and callback-table pointers.
  Callback table VA/file-offset values and callback VA/RVA/target-file-offset
  values are also exposed in `Tls` plus prefixed `tls:*` strings.
- Resource directory types and resource data entries, including data RVA, raw
  file offset, size, bounded entropy, and entropy labels where bytes are
  available.
- RT_VERSION key/value strings such as `CompanyName`, `FileDescription`,
  `FileVersion`, `OriginalFilename`, and `ProductName`, emitted as
  `version:<key>=<value>` evidence and low-risk `version_*` tags.
- RT_MANIFEST metadata for requested execution level, `autoElevate`, and
  `uiAccess`, emitted as `manifest:*` evidence. These are triage metadata and
  are not treated as malicious without corroborating behavior.
- Debug directory entries, including CodeView RSDS/NB10 metadata and bounded
  PDB paths, emitted as `debug:*` evidence and low-risk `debug_*` tags.
- Overlay bytes after the last mapped section raw-data end, with certificate
  table bytes separated from appended non-certificate data where possible.
  The normalized overlay offsets, sizes, certificate overlap, and entropy are
  also exposed in `Overlay`.

Resource tags include `resources_present`, `resource_type_rcdata`,
`resource_manifest`, `resource_version_info`, `resource_icon`,
`resource_payload_candidate`, `resource_large_data`,
`resource_high_entropy_data`, `resource_very_high_entropy_data`, and
`resource_embedded_pe`. Version/manifest metadata tags include
`version_info_present`, `version_info_string`, `version_companyname`,
`version_fileversion`, `version_originalfilename`,
`manifest_resource_string`, `manifest_requested_execution_level`,
`manifest_require_administrator`, `manifest_highest_available`,
`manifest_auto_elevate`, and `manifest_ui_access`.

Debug tags include `debug_directory_present`, `debug_codeview_present`,
`debug_rsds_present`, `debug_nb10_present`, `debug_pdb_path`,
`debug_pdb_path_absolute`, `debug_pdb_build_path`,
`debug_reproducible_build`, and `debug_type_<type>`. Debug/PDB evidence is
useful for provenance and build-path triage; it should not be scored as
high-risk by itself.

Section tags include `high_entropy_section`, `very_high_entropy_section`,
`low_entropy_section`, `virtual_only_section`, `oversized_virtual_section`,
`executable_section`, `writable_section`, and
`writable_executable_section`. Packer-hint tags are deliberately coarse:
`packer_hint` is set only alongside packer section names or known packer
strings, while `packer_section_name`, `packer_upx`, and `packer_string_hint`
carry the more specific evidence.

Overlay/signature tags include `overlay_present`, `pe_overlay`,
`overlay_contains_certificate_table`, `overlay_certificate_table_only`,
`overlay_non_certificate_data`, `overlay_large_data`,
`overlay_high_entropy`, `security_directory_present`,
`digital_signature_present`, `authenticode_signature_present`,
`signature_pkcs_signed_data`, `invalid_security_directory`,
`invalid_certificate_table`, and `certificate_table_unparsed`. Evidence is
emitted as prefixed strings such as `overlay:start=...`,
`overlay:non-certificate@...`, `signature:certificate-table@...`, and
`signature:certificate[...]`.

## String and indicator coverage

String scanning is capped at 32 MiB and extracts printable ASCII plus simple
UTF-16LE strings. Current labels include:

- URLs and network indicators: `url`, `embedded_url`, `domain_name`,
  `domain_indicator_string`, `tor_domain_string`,
  `dynamic_dns_domain_string`, `ip_address`, `public_ip_address`,
  `private_or_reserved_ip_address`, `email_address`.
- Paths: `windows_path_string`, `file_path_string`, `temp_path_string`,
  `appdata_path_string`, `registry_path_string`,
  `run_key_path_string`, `service_registry_path_string`,
  `scheduled_task_registry_path_string`, `scheduled_task_path_string`,
  `startup_folder_path_string`, `environment_path_string`.
- Execution strings: `script_execution_string`, `powershell_string`,
  `encoded_command_string`, `lolbin_string`, `download_command_string`,
  `exfil_command_string`.
- Persistence strings: `persistence_string`, `service_string`,
  `scheduled_task_string`, and the compatibility alias `task_string`.
  Service and scheduled-task string tags require specific registry/API/path
  markers or command switches such as `sc.exe create` or `schtasks /create`;
  generic words like "service" or "task" are not enough.
- Credential and defense-evasion strings: `credential_access_string`,
  `defense_evasion_string`.
- Anti-analysis strings: `anti_analysis_string`,
  `sandbox_evasion_string`, `debugger_evasion_string`.
- Packer strings: `packer_string_hint`.

## Import/API grouping

Import and fallback API-string tags are grouped to keep rules concise:

- Injection: `import_process_injection_api`
- Dynamic code: `import_dynamic_code_api`
- Network/download/upload: `import_network_api`, `import_network_library`,
  `import_download_api`, `import_exfil_api`
- Persistence: `import_persistence_api`,
  `import_registry_persistence_api`, `import_service_persistence_api`
- File drop/release: `import_file_drop_api`
- Script/process launch: `import_script_execution_api`
- Resource extraction: `import_resource_api`
- Anti-analysis: `import_anti_analysis_api`
- Credential access: `import_credential_access_api`,
  `import_credential_access_library`
- Defense evasion: `import_defense_evasion_api`,
  `import_defense_evasion_library`

All grouped API hits also set `import_suspicious_api` for broad triage.
When suspicious imported APIs are present, aggregate rollups add
`import_suspicious_api_cluster`; two or more behavior clusters add
`import_multi_suspicious_api_cluster`. These tags are intentionally broad and
the copyable `import-api-cluster:*` evidence carries the cluster hit counts for
report triage. Report JSON consumers should prefer the structured
`ImportApiClusters` field when available and fall back to legacy prefixed
`InterestingStrings` for older reports.

## Static notes / YARA boundary

`rules/static-notes.yar` is an optional lightweight YARA-style entry point. If
the file is present under a discovered repository/app root, `StaticAnalyzer`
applies a small built-in matcher against the same bounded static scan buffer
used for string extraction. No native YARA binary or large dependency is
required. If the rule file is missing, too large, unreadable, or uses syntax
outside the supported subset, static analysis silently falls back to the
built-in PE/string heuristics without adding warnings.

The built-in matcher intentionally supports only the static-notes subset:

- `rule`, `meta`, `strings`, and `condition` sections.
- Literal strings with `ascii`, `wide`, and `nocase` modifiers.
- Regex strings against a Latin-1 projection of the bounded scan buffer.
- `uint16(0) == 0x5A4D`, `$id`, `any/all/N of them`,
  `any/all/N of ($prefix*)`, parentheses, `and`, `or`, and `not`.

Matched rules add rule-facing `static.yara.*` tags into
`StaticAnalysisResult.Tags`, including `static.yara.match`,
`static.yara.engine.builtin`, `static.yara.rule.<rule-id>`, and optional
`static.yara.scope.<scope>` / `static.yara.mitre.<technique>` tags from rule
metadata. Copyable evidence is also added to `InterestingStrings` as
`static.yara.match:<rule>`, `static.yara.strings:<rule>:<ids>`, and
`static.yara.meta:<rule>:...` values.

The existing `static.analysis.completed` event carries these tags through
`Data["tags"]`, and `StaticAnalyzer.CreateEvents` also projects direct
`static.yara.match` rows with `ruleName`, `engine`, optional `matchedStringIds`,
`scope`, and `mitre` data fields. Behavior rules consume the direct
`static.yara.match` event as low-confidence static triage while keeping the
summary tags for older reports.

## Rule integration

`SandboxJobService` emits `static.analysis.completed` with
`Data["tags"]` set to a comma-joined copy of `StaticAnalysisResult.Tags`.
Rules under `rules/behavior-rules.json` still use `dataContains.tags`
predicates for backward-compatible reports, and now also consume structured
`static.pe.import.module`, `static.pe.import.cluster`, `static.string.*`,
`static.packer.hint`, and `static.yara.match` events when those rows are
present. Direct structured events remain static triage: their rule IDs start
with `static-`, carry `static` tags, and do not promote static-only evidence to
primary runtime behavior.

The smoke scenario
`tests/KSword.Sandbox.SmokeTests/Scenarios/StaticRulesMitreScenario.cs`
validates that:

1. Static and dynamic behavior rules load.
2. Rule-referenced MITRE IDs exist in `rules/mitre-windows-map.json`.
3. Synthetic static tags classify into expected findings.
4. Synthetic files produce URL/domain/IP/path/script/anti-analysis/resource tags.
5. A synthetic PE contract sample emits overlay and certificate-table evidence
   without requiring Authenticode validation libraries.
6. A synthetic PE contract sample exposes structured imports, suspicious API
   clusters, exports, TLS callbacks, overlay details, section entropy/flags,
   URL/domain/IP/email indicators, registry/filesystem paths,
   LOLBIN/download command strings, and credential/defense-evasion string tags.

The smoke scenario
`tests/KSword.Sandbox.SmokeTests/Scenarios/BehaviorRuleStaticEventConsumptionScenario.cs`
adds a focused rule-consumption gate for the direct structured static events. It
parses `behavior-rules.json`, checks rule ID uniqueness, classifies synthetic
`static.pe.import.*`, `static.string.*`, `static.packer.hint`, and
`static.yara.match` rows, and verifies that these static-only findings stay
non-high-risk triage.

## False-positive guardrails

Static tags are triage evidence, not a verdict. The analyzer avoids adding
high-risk semantics for metadata-only observations:

- Public IPs, domains, PDB paths, version strings, manifest attributes, debug
  directories, and signatures remain metadata unless runtime telemetry or
  stronger static clusters corroborate them.
- LOLBin/service/scheduled-task tags require command-like context or specific
  registry/API/path markers.
- Packer hints are intentionally separated from generic high-entropy section
  tags so packed/installer-like benign software does not become high severity
  from entropy alone.
- Reference-only URL/domain string indicators (`classification=reference`) are
  preserved as raw evidence but excluded from embedded URL/domain rule hits.
