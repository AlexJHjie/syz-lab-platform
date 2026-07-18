# syzrun

`syzrun` 是一个运行于 Ubuntu 的 Linux 内核漏洞复现工具。它读取单个 syzbot 风格的漏洞元数据 JSON，自动完成：

1. 下载内核配置、syz reproducer 和 crash report。
2. 检出并编译指定版本的 Linux 内核。
3. 检出并编译指定版本的 syzkaller。
4. 使用 QEMU 启动目标内核并执行 syz reproducer。
5. 最多进行 3 次复现尝试，生成 JSON 和 Markdown 报告。

当前主要支持 `amd64` 和 `syz-reproducer`。JSON 中自带的 patch 不会自动应用；验证补丁时需要通过 `--patch` 显式传入。

## 运行环境

- Ubuntu Linux
- Python 3.10 或更高版本
- Conda 环境：`kRepair`
- QEMU/KVM
- Git、Go、GCC/Clang 和 Linux 内核编译依赖
- 建议至少预留 30 GB 磁盘空间

## 1. 安装系统依赖

进入项目根目录：

```bash
cd /path/to/platform
```

赋予脚本执行权限并安装 Ubuntu 依赖：

```bash
chmod +x scripts/*.sh examples/*.sh
./scripts/install_ubuntu_deps.sh
```

脚本会通过 `apt` 安装 QEMU、Git、Go、debootstrap、rootfs 工具和内核构建依赖，需要
`sudo` 权限。漏洞要求的精确版本编译器不由该脚本安装，需按“精确内核工具链”一节准备。

## 2. 配置 Conda 环境

激活已有的 `kRepair` 环境：

```bash
conda activate kRepair
```

确认 Python 版本：

```bash
python --version
```

如果环境尚未创建，可执行：

```bash
conda create -n kRepair python=3.11 pip -y
conda activate kRepair
```

在项目根目录以可编辑模式安装：

```bash
python -m pip install -e .
```

验证 CLI：

```bash
which syzrun
syzrun --help
syzrun run --help
```

更新项目代码后，如 CLI 或包结构发生变化，可重新执行 `python -m pip install -e .`。

## 3. 创建 QEMU rootfs

首次运行前创建 Debian rootfs 镜像和 SSH 密钥：

```bash
./scripts/create_rootfs.sh work/cache/rootfs
```

该过程需要 `sudo`，完成后应生成：

```text
work/cache/rootfs/rootfs.img
work/cache/rootfs/id_rsa
work/cache/rootfs/id_rsa.pub
```

已有 rootfs 时不需要重复创建。脚本检测到 `rootfs.img` 后会直接复用。

需要 Atheros AR9271 固件的漏洞使用独立镜像：

```bash
./scripts/create_rootfs-firmware.sh
```

完成后应生成：

```text
work/cache/rootfs-firmware/rootfs.img
work/cache/rootfs-firmware/id_rsa
work/cache/rootfs-firmware/id_rsa.pub
```

脚本安装 Debian `firmware-ath9k-htc` 和 `firmware-atheros` 包，并确认镜像内存在
`/lib/firmware/ath9k_htc/htc_9271-1.4.0.fw`。该镜像由
`configs/vulnerabilities.json` 中的漏洞专用 `rootfs` 配置选择。

## 4. 配置 KVM

检查 KVM：

```bash
ls -l /dev/kvm
```

如果当前用户没有权限：

```bash
sudo usermod -aG kvm "$USER"
```

随后注销并重新登录，再执行 `conda activate kRepair`。没有 KVM 时可以禁用硬件加速，但复现速度会明显降低：

```bash
export PLATFORM_DISABLE_KVM=1
```

## 5. 准备漏洞元数据

输入文件是一个 JSON 文件，至少应在 `crashes[0]` 中包含：

- `kernel-source-git`
- `kernel-source-commit`
- `kernel-config`
- `syzkaller-git`
- `syzkaller-commit`
- `syz-reproducer`
- `compiler-description`
- `architecture`
- `crash-report-link`

项目使用 `crashes[0]` 作为本次复现目标，并使用顶层的 `id`、`title` 和 `display-title` 生成运行目录和判断复现结果。

## 6. 执行漏洞复现

基本命令：

```bash
syzrun run /path/to/vulnerability.json
```

推荐显式设置工作目录和构建步骤超时：

```bash
syzrun run /path/to/vulnerability.json \
  --work-dir work \
  --timeout 2h
```

例如：

```bash
syzrun run ../dataset/0084fd109a7a10011e183a357715c91cff2cacb0.json \
  --work-dir work \
  --timeout 2h
```

`--timeout` 支持纯秒数以及 `s`、`m`、`h`、`d` 后缀，例如 `600`、`30m`、`2h`。

也可以使用示例脚本：

```bash
TIMEOUT=2h WORK_DIR=work ./examples/run_one.sh /path/to/vulnerability.json
```

## 7. 验证外部补丁

使用 `--patch` 在内核构建前应用补丁：

```bash
syzrun run /path/to/vulnerability.json \
  --patch /path/to/fix.patch \
  --work-dir work \
  --timeout 2h
```

不带 `--patch` 时复现原始内核；带上后用于观察补丁是否阻止目标漏洞复现。

## 8. 输出目录

假设漏洞 ID 为 `<vuln-id>`，默认产物位于：

```text
work/
  cache/
    downloads/
    linux.git/
    syzkaller.git/
    rootfs/
  runs/
    <vuln-id>/
      input/
        vuln.json
        kernel.config
        repro.syz
        crash.report
        user.patch
      kernel/
        linux/
      syzkaller/
        src/
      logs/
        kernel-git.log
        kernel-build.log
        kernel-patch.log
        syzkaller-git.log
        syzkaller-build.log
        attempt-01/
          qemu.log
          ssh.log
          scp.log
          repro.log
          crash.log
        attempt-02/
        attempt-03/
      report.json
      report.md
```

每个 `attempt-*` 目录可能包含 `qemu.log`、`ssh.log`、`scp.log` 和 `repro.log`。当目标漏洞被成功复现时，平台使用对应 syzkaller commit 构建的 `syz-symbolize` 和本次构建的 `vmlinux` 生成 `crash.log`，其中只保留目标 crash 报告及其源码行号和内联调用信息。符号化失败时会记录 warning 且不生成 `crash.log`，但不会改变复现结论；平台不会回退到其他符号化方法。`crashed_other`、`not_reproduced` 和 `failed` 不生成该文件。每次重新运行同一漏洞时，运行日志会被清空，但共享下载和 Git mirror 缓存会被保留。


查看结果：

```bash
cat work/runs/<vuln-id>/report.md
cat work/runs/<vuln-id>/report.json
```

查看构建或复现日志：

```bash
less work/runs/<vuln-id>/logs/kernel-build.log
less work/runs/<vuln-id>/logs/syzkaller-build.log
less work/runs/<vuln-id>/logs/attempt-01/qemu.log
less work/runs/<vuln-id>/logs/attempt-01/crash.log
less work/runs/<vuln-id>/logs/attempt-01/repro.log
```

## 9. 结果与退出码

报告中的 verdict 可能是：

- `reproduced`：匹配到目标崩溃标题，或匹配到崩溃类型和函数。
- `crashed_other`：内核发生崩溃，但未匹配目标漏洞。
- `not_reproduced`：所有尝试均未发现目标崩溃。
- `failed`：所有复现尝试均因基础设施或运行错误失败。

CLI 退出码：

- `0`：`reproduced` 或 `crashed_other`
- `1`：`not_reproduced`
- `2`：执行失败或 verdict 为 `failed`

## 10. 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PLATFORM_SYZBOT_BASE_URL` | `https://syzkaller.appspot.com` | syzbot 相对链接的基础地址 |
| `PLATFORM_LINUX_REPO` | torvalds/linux | Linux mirror 仓库地址 |
| `PLATFORM_SYZKALLER_REPO` | google/syzkaller | syzkaller mirror 仓库地址 |
| `PLATFORM_QEMU_MEM` | `2048` | QEMU 内存，单位 MB |
| `PLATFORM_QEMU_SMP` | `2` | QEMU vCPU 数量 |
| `PLATFORM_DISABLE_KVM` | 未设置 | 设为 `1` 时禁用 KVM |
| `PLATFORM_SYMBOLIZER_TIMEOUT` | `300` | `syz-symbolize` 超时时间，单位秒 |
| `PLATFORM_ROOTFS_SIZE` | `8G` | 创建 rootfs 时的镜像大小 |
| `PLATFORM_DEBIAN_SUITE` | `bookworm` | 创建 rootfs 时使用的 Debian 版本 |
| `PLATFORM_DEBIAN_MIRROR` | `http://deb.debian.org/debian` | debootstrap 软件源 |
| `GITHUB_TOKEN` | 未设置 | 下载私有 GitHub Release 工具链时使用，令牌仅需仓库 `Contents: read` 权限 |

## 精确内核工具链

内核编译前，`syzrun` 会解析 metadata 的 `compiler-description`，并在项目根目录的
`platform/toolchains/` 查找完整版本匹配的 GCC/Clang 和 binutils。该目录是项目级
持久资源，不受 `--work-dir` 影响，也不会随临时工作区清理。

工具链通过 make 命令行变量（如 `CC=...`、`LD=...`）传入，避免被 Linux
Makefile 的默认值覆盖。运行 `syz-symbolize` 时也会把该工具链目录置于 `PATH`
最前面，使其使用配套的 `addr2line`。工具链目录不存在或实际版本不匹配时会直接失败，并提示用户将
工具链手动下载到指定目录；平台不会自动下载，也不会静默回退到系统编译器。

目录名由严格版本自动确定，例如：

```text
platform/toolchains/gcc-8.0.1/
platform/toolchains/gcc-10.2.1-binutils-2.35.2/
```

工具链统一使用以下目录结构：

```text
platform/toolchains/<严格版本目录>/
├── bin/
│   ├── gcc            # Clang 工具链则为 clang
│   ├── ld
│   ├── as
│   ├── ar
│   ├── nm
│   ├── objcopy
│   ├── objdump
│   ├── readelf
│   ├── strip
│   └── addr2line
└── lib/               # 可选，存放工具链运行所需共享库
```

`bin/gcc`（或 `bin/clang`）是固定入口，不再递归搜索任意解压布局。如果
`compiler-description` 指定了 binutils 版本，则上述 binutils 工具必须全部存在，
且 `bin/ld --version` 必须严格匹配。入口可以使用相对软链接指向目录内保留的原始文件。

工具链缺失时，平台会以退出码 `2` 安全停止，不打印 Python traceback。错误信息会列出：

- `compiler-description` 原文；
- 需要下载的 GCC/Clang 和 binutils 版本；
- 应创建的目标目录；
- `bin/` 下要求的固定文件名；
- 本地版本检查命令。

同时仍会生成 `failure.json`，其中 `failure_kind` 为 `toolchain_unavailable`。

项目提供显式工具链初始化脚本。工具链发布者先在
`configs/toolchains.lock.json` 中填写预编译压缩包的 HTTPS URL 和 SHA256；使用者随后
可以一次安装清单中的全部工具链：

```bash
./scripts/setup_toolchains.sh
```

也可以只安装指定版本：

```bash
./scripts/setup_toolchains.sh gcc-8.0.1
./scripts/setup_toolchains.sh gcc-10.2.1-binutils-2.35.2
```

压缩包必须以严格版本目录为唯一顶层目录，例如
`gcc-8.0.1/bin/gcc`。脚本仅接受 HTTPS 或本地 `file://` URL，下载后严格校验
SHA256，并在原子迁移到 `platform/toolchains/` 前再次检查编译器和 binutils
版本。`syzrun run` 自身仍只检测工具链，不会隐式联网下载。

清单使用私有 GitHub Release Asset API URL 时，安装前需通过环境变量提供只读令牌：

```bash
GITHUB_TOKEN="$(gh auth token)" ./scripts/setup_toolchains.sh
```

也可以使用 `GH_TOKEN`。令牌不得写入清单或提交到 Git。

## 11. 常见问题

### `syzrun: command not found`

确认 Conda 环境和安装状态：

```bash
conda activate kRepair
python -m pip install -e .
which syzrun
```

### rootfs 或 SSH key 不存在

```bash
./scripts/create_rootfs.sh work/cache/rootfs
```

如果 `--work-dir` 不是 `work`，默认 rootfs 应放在对应的
`<work-dir>/cache/rootfs/` 中。漏洞专用 rootfs 在
`configs/vulnerabilities.json` 中配置。

### QEMU 启动很慢

检查 `/dev/kvm` 是否存在，以及当前用户是否属于 `kvm` 组：

```bash
groups
ls -l /dev/kvm
```

### 构建失败

优先检查：

```bash
less work/runs/<vuln-id>/logs/kernel-git.log
less work/runs/<vuln-id>/logs/kernel-build.log
less work/runs/<vuln-id>/logs/syzkaller-git.log
less work/runs/<vuln-id>/logs/syzkaller-build.log
```

## 12. 运行测试

在 `kRepair` 环境中执行：

```bash
conda activate kRepair
python -m unittest discover -s tests
```

## 当前限制

- 当前仅支持 `amd64`/`x86_64`。
- 当前只执行 syz reproducer，不执行 C reproducer。
- 每个漏洞最多进行 3 次复现尝试，每次复现执行上限为 2 分钟。
- Linux 和 syzkaller 工作树会执行 `git reset --hard` 和 `git clean -fdx`，不要在生成的工作树中保存手工修改。

## Per-vulnerability runtime profiles

部分漏洞需要额外的构建参数或 QEMU 启动参数。`syzrun` 会自动读取
`configs/vulnerabilities.json`，并根据 metadata 中的 `id` 应用匹配配置。

示例：

```json
{
  "vulnerabilities": {
    "0084fd109a7a10011e183a357715c91cff2cacb0": {
      "build_env": {
        "KCFLAGS": "-fcf-protection=none"
      },
      "make_args": [],
      "qemu_append": [
        "systemd.unified_cgroup_hierarchy=0"
      ],
      "qemu_args": [],
      "repro_env": {}
    },
    "0518799fc2250353125d212fc510c44adbde73c3": {
      "rootfs": {
        "image": "cache/rootfs-firmware/rootfs.img",
        "ssh_key": "cache/rootfs-firmware/id_rsa"
      }
    }
  }
}
```

当前支持字段：

- `build_env`: 注入 kernel build 命令的环境变量。
- `make_args`: 追加到 kernel `make bzImage` 命令的参数。
- `qemu_append`: 追加到 QEMU `-append` 的 Linux kernel command line。
- `qemu_args`: 追加到 QEMU 命令末尾的参数。
- `repro_env`: 预留给 reproducer 运行环境变量。
- `rootfs`: 为当前漏洞选择专用 guest rootfs；`image` 和 `ssh_key` 必填，
  `ssh_user` 可选并默认为 `root`。相对路径以 `--work-dir` 为基准。


## Python API

外部自动修复系统可以直接调用 Python API，避免解析 CLI stdout：

```python
from pathlib import Path

from syzrun.api import RunOptions, run_vulnerability

result = run_vulnerability(
    RunOptions(
        metadata=Path("kBenchSYZ/0084fd109a7a10011e183a357715c91cff2cacb0.json"),
        patch=Path("candidate.patch"),
        work_dir=Path("work"),
        timeout="20m",
    )
)

print(result.exit_code)
print(result.report.verdict_status if result.report else result.error)
print(result.report_json or result.failure_json)
```

`RunResult.report` 是 `RunReport | None`，成功完成验证流程时可读取
`verdict_status`、`verdict_reason` 和 `verdict_matched`。基础设施失败时
`report` 为 `None`，错误信息在 `error`，失败报告路径在 `failure_json`。

`failure_json` 示例：

```json
{
  "vuln_id": "abc",
  "status": "failed",
  "failure_stage": "kernel_patch",
  "failure_kind": "apply_failed",
  "error": "command failed (1): patch -p1 --forward -i .../input/user.patch",
  "command": "patch -p1 --forward -i .../input/user.patch",
  "exit_code": 1,
  "duration_seconds": 12.3,
  "timed_out": false,
  "logs_dir": ".../runs/abc/logs",
  "log_path": ".../runs/abc/logs/kernel-patch.log",
  "patch_path": ".../runs/abc/input/user.patch",
  "patch_sha256": "...",
  "work_dir": ".../runs/abc"
}
```

`failure_stage` 当前取值包括：`metadata_load`、`asset_fetch`、
`kernel_checkout`、`kernel_patch`、`kernel_build`、`syzkaller_checkout`、
`syzkaller_build`、`vm_boot`、`reproduce`、`report_parse`、`infra`。

`failure_kind` 当前取值包括：`invalid_metadata`、`download_failed`、
`checkout_failed`、`apply_failed`、`compile_error`、`timeout`、
`command_failed`、`vm_failed`、`repro_failed`、`parse_failed`、
`internal_error`。

也可以只准备 Linux 源码，供外部 PatchAgent 复用同一份 mirror/cache，不执行
build、boot 或 repro：

```python
from pathlib import Path

from syzrun.api import ensure_kernel_source

source_path = ensure_kernel_source(
    metadata=Path("kBenchSYZ/0084fd109a7a10011e183a357715c91cff2cacb0.json"),
    work_dir=Path("work"),
    dest=Path("work/patchagent-sources/0084fd109a7a10011e183a357715c91cff2cacb0/linux"),
    timeout="20m",
)
```

如果不传 `dest`，默认 checkout 到
`<work_dir>/patchagent-sources/<vuln_id>/linux`。
