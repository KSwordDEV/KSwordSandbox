# KSwordSandbox packaging manifests

中文优先提示：便携打包只做本机 staging/zip，不发布、不推送；manifest 和
`scripts/package-portable.ps1` 的硬性规则会排除本机 secret、`install-state.json`、
DPAPI 备份、`.env`、样本、报告、VM 磁盘/快照、仓库二进制、符号和签名材料。

This directory contains the first productization-facing package manifests:

- `source-package.manifest.json` defines the source-release include roots and
  the hard exclusions for samples, VM state, generated build output, archives,
  runtime reports, local secrets, and signing material.
- `runtime-package.manifest.json` defines a portable runtime layout that copies
  operator scripts/docs/config/rules from the repository and copies published
  binaries only from an external `RuntimePublishRoot`. The runtime manifest
  includes both root wrappers and `scripts/` wrappers, including driver status
  management, but never copies repository `bin/`, `obj/`, `x64/`, VM, report,
  sample, or local secret files.

Use `scripts/package-portable.ps1` to stage a local package tree and optionally
create a `.zip` under an output directory outside the repository. The script is
local-only and intentionally has no push/publish step.
