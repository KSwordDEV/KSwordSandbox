# Workstation VIX GuestOps 原型

vix_probe.cpp 是独立传输 helper 原型。它从当前进程环境中的
KSWORDBOX_GUEST_PASSWORD 读取专用来宾账号密码，在进程内调用
VixVM_LoginInGuest；命令行只含操作、VMX 路径和文件或程序路径，
不含密码。用户名可用 KSWORDBOX_GUEST_USER 指定，默认 SandboxUser。

发布构建机需要 VMware VIX SDK 的 vix.h、Vix64AllProducts.lib 与
Visual Studio C++ 工具链。`build.cmd` 默认从 Program Files (x86)
查找 SDK，并通过 `vswhere` 查找编译器；也可设置 `VIX_SDK_ROOT` 与
`VIX_OUT_DIR`。默认编译产物位于 `artifacts/_build/vix-probe/`，不提交二进制。
`scripts/Publish-RuntimePayloads.ps1` 在发布时编译 helper，将其与
`Invoke-VmwareOfflineRunbook.ps1` 放入 `tools/vix-helper/`。
运行机需安装 VMware Workstation 和 Microsoft Visual C++ 2015–2022 x64
运行时；VIX SDK 仅是构建依赖，不随包分发。

    .\tools\KSword.Sandbox.VixProbe\build.cmd
    $helper = 'artifacts\_build\vix-probe\vix_probe.exe'
    $vmx = '<path-to-your-disposable-isolated-vm.vmx>'
    & $helper status $vmx
    & $helper file-exists $vmx 'C:\Windows\System32\notepad.exe'
    & $helper copy-to $vmx <host-source> <guest-destination>
    & $helper run $vmx <guest-program> '<complete argument string>'
    & $helper copy-from $vmx <guest-source> <new-host-destination>

默认 VIX 作业等待上限为 180 秒；可通过 KSWORDBOX_VIX_TIMEOUT_SECONDS
设为 1–3600 秒。返回码：0=成功、1=VIX/传输/超时失败、2=命令格式错误、
3=来宾文件不存在、4=来宾程序非零退出。标准输出只写状态与退出码，
错误只写数值错误码；不会记录完整调用、密码或来宾文件内容。
copy-from 拒绝覆盖已有宿主文件。

## 2026-10-26 无害克隆实测

在断开 NIC、关闭 USB、HGFS 发布 0 个共享的独立 Windows 10 克隆上：

- status、进程内登录及来宾文件查询成功；
- copy-to、file-exists、run、copy-from 均成功；
- 无害文本往返 SHA-256 一致；来宾 PowerShell 脚本生成的文本可回收；
- 不存在文件返回 3，来宾 exit 7 返回 4，目标已存在时拒绝覆盖；
- 1 秒作业上限成功触发超时并返回 1。超时后的后端操作可能继续。

验证后已软关机并回滚 Baseline-Isolated-20261026；原机未启动。
这些结果不代表任何破坏性样本已运行。

## 正式运行包

VMware Block 运行手册通过 `vmware.vixHelperPath` 使用此 helper。
该配置留空时，配置加载器在已发布包的 `tools/vix-helper/` 中查找。
离线运行脚本负责调用传输原语及证据回收策略；helper 本身仅提供
GuestOps 传输命令。

密码虽不在命令行，但仍短暂存在于 helper 进程内存和启动时继承的环境；
同级权限的宿主进程或调试者仍可能读取。原型未验证 crash dump、
VMware 内部日志和所有 Unicode 路径行为，不应单凭本次验证声明密码
完全不可见。仅使用专用来宾账号，批次后轮换凭据。
