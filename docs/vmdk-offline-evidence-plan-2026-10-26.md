# VMware 破坏后离线取证可行性（2026-10-26）

## 结论

当前通用 VM 运行器可在 GuestOps 尚存活时回收 Agent 的刷盘 `sample-launch-proof.json`；一旦来宾很快失联且未回收该文件，**不能从 Agent PID 或 GuestOps 失联推断样本已经启动，更不能推断文件或磁盘已被擦除**。进一步验证需要在停机后、快照回滚前读取当前 VMDK 叶子及其父链。当前主机尚无经验证可直接完成这项工作的只读取证管线。

## 本机只读工具盘点

- `D:\Software\Vmware\vmware-vdiskmanager.exe`（build 20904516）提供 `-r <source-disk> -t 0 <destination-disk>` 转换链、`-e` 链一致性检查。它没有显式“只读打开源盘”开关；尚未验证源盘不被修改。
- `C:\Program Files\7-Zip\7z.exe` 声明支持 VMDK、MBR 和 NTFS。但其命令行不能在多个分区的 VMDK 中直接跨两层选取某个 NTFS 文件，且不能把快照 delta 当作已合并的磁盘。
- 未安装 `qemu-img`、`pytsk3`、`pyvmdk`、The Sleuth Kit，或 VDDK 的 `vixDiskLib.dll`。Workstation 自带 `vixDiskMountApi.dll`，其导出为内部 `VixDiskMount_*` 接口，不能直接代替公开 VDDK `VixDiskLib_Read` API。
- 没有启用 WSL 发行版。当前不能借用 Linux 取证工具。

仅用 **2 MB 合成 VMDK** 试验 VMware 转换前置时，该工具因本机 `preferences.ini.lck` 创建失败而退出，留下一个 0 字节目标。没有读取或修改任何真实 VM 磁盘，转换和 NTFS 提取尚未实证。这个测试结果不能外推为真实磁盘损坏。

## 可实现的通用方案

1. 运行器先确认隔离克隆已经完全停机；在回滚前冻结 VMX 当前磁盘引用、VMDK 叶子描述符和父链的路径及哈希，检查每段 `CID`/`parentCID` 一致，不靠文件名猜测链。
2. 首选正式 VDDK：对当前**叶子描述符**调用 `VixDiskLib_Open` 的 `VIXDISKLIB_FLAG_OPEN_READ_ONLY`，由库组合父链；只用 `VixDiskLib_Read` 读取扇区和文件系统所需字节。对基线快照以同样方式读取同一逻辑扇区，记录前后 SHA-256 和偏移。源盘不可被挂载为可写卷。
3. 用 NTFS 只读解析器提取允许列表内的 `sample-launch-proof.json`、Agent 部分事件、种植清单与受控诱饵元数据。逐个验证 job ID、样本路径、来宾预启动 SHA-256、字节数、PID 和时间；只取数据，不把样本 EXE 解出或执行到宿主。
4. 将比较分成三层证据：有效 launch proof 证明启动；受控诱饵前后内容或元数据证明文件改变；相同逻辑偏移的磁盘扇区前后差异证明磁盘改变。仅有扇区差异仍需排除正常 Windows 写入和 VMware 元数据变化；仅有失联不属于破坏证据。
5. 生成带 `source=offline-vmdk-readonly`、链哈希、扇区范围、读错误与采集时间的证据清单，之后才回滚基线。任何读取/解析失败写为缺口，报告维持“不可判定”。

若先采用已装工具，需在**另一份完整磁盘链副本**上试验 `vmware-vdiskmanager -r` 展平，然后用独立 NTFS 解析器读文件。因为该工具没有显式只读源盘保证、7-Zip CLI 也不能直达嵌套文件，这条路线尚不足以接入自动运行器。不能在真实克隆上直接试验并把试验结果算成样本行为。

## 技术依据

- [Broadcom Virtual Disk API：只读打开和扇区读取](https://developer.broadcom.com/xapis/virtual-disk-api/latest/vddkFunctions.6.4.html)
- [Broadcom Virtual Disk API：打开叶子磁盘时组合父链](https://developer.broadcom.com/xapis/virtual-disk-api/latest/vddkFunctions.6.7.html)
- [7-Zip 官方格式列表](https://www.7-zip.org/)
- [7-Zip 作者对多分区镜像 CLI 二级打开限制的答复](https://sourceforge.net/p/sevenzip/discussion/45798/thread/312f8ee23d/)
