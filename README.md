# syzrun

`syzrun` 是面向 Ubuntu 的 Linux 内核漏洞复现工具。它读取单个 syzbot 风格的漏洞元数据，自动下载复现材料、构建指定版本的 Linux 与 syzkaller、启动 QEMU 执行 reproducer，并输出 JSON 和 Markdown 报告。

当前支持 `amd64`/`x86_64` 和 syz reproducer。每个漏洞最多尝试 3 次；元数据内的补丁不会自动应用，验证补丁时必须显式传入 `--patch`。

## 环境要求

- Ubuntu Linux、Python 3.10+
- Conda、Docker、QEMU/KVM、Git、Go
- 宿主机 GCC/G++、Make（用于构建 syzkaller）；Linux 内核构建依赖由容器提供
- 建议预留至少 30 GB 磁盘空间

## 首次安装

在项目根目录执行 `start.sh`，一键安装宿主机依赖、全部精确工具链和各类 QEMU rootfs：

```bash
./scripts/start.sh all
```

安装过程需要 `sudo` 权限。各步骤依次执行，某一步失败后会继续执行后续步骤，最后汇总失败项；存在失败项时返回非零退出码。
若工具链下载涉及私有 GitHub Release，需提前设置具有只读权限的 `GITHUB_TOKEN`。

随后创建并激活 Python 环境：

```bash
conda env create -f environment.yml
conda activate platform
python -m pip install -e .
```

确认安装成功：

```bash
syzrun --help
syzrun run --help
```

工具链保存在 `toolchains/<工具链名称>/`，可安装项见 `configs/toolchains.lock.json`。
内核必须使用元数据 `compiler-description` 指定的精确编译器版本；`syzrun run` 只检查工具链，不会自动下载或回退到系统编译器。
各类 rootfs 默认保存在 `work/cache/` 下，由 `configs/vulnerabilities.json` 按漏洞选择。
运行前还需按下文配置内核构建容器镜像。

默认启用 KVM。确认当前用户可访问 `/dev/kvm`；若无 KVM，可使用较慢的软件虚拟化：

```bash
export PLATFORM_DISABLE_KVM=1
```

## 操作指南

### 1. 准备元数据

输入为单个 JSON 文件。程序读取 `crashes[0]`，其中必须包含：

```text
syz-reproducer          kernel-config
kernel-source-git       kernel-source-commit
syzkaller-git           syzkaller-commit
compiler-description    architecture
crash-report-link
```

顶层建议提供 `id`、`title` 和 `display-title`；`id` 用作运行目录名。

### 2. 复现漏洞

所有 case 的内核均使用容器构建；必须配置构建镜像。默认使用第二版镜像，基于 Ubuntu 24.04 LTS：

```bash
docker build -t syzrun-kernel-build:v2 containers/kernel-build-v2
cp .env.example .env
# 在 .env 中配置 PLATFORM_KERNEL_BUILD_IMAGE=syzrun-kernel-build:v2
```

第一版 Ubuntu 18.04 镜像保留在 `containers/kernel-build-v1`，用于需要旧用户态的内核；
v1 中的旧 SELinux 头文件检查不适用于 Ubuntu 24.04，因此 v2 不包含该检查。
如终端已导出 `PLATFORM_KERNEL_BUILD_IMAGE`，需同步更新或取消该变量，才能使用 `.env` 中的 v2 配置。

```bash
syzrun run /path/to/vulnerability.json \
  --work-dir work \
  --timeout 30m
```

参数说明：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `metadata` | 必填 | 漏洞元数据 JSON |
| `--work-dir` | `work` | 缓存、构建、日志和报告目录 |
| `--timeout` | `30m` | 长耗时步骤上限；支持 `600`、`30m`、`2h`、`1d` |
| `--patch` | 无 | 构建内核前应用的外部补丁 |

### 3. 验证补丁

```bash
syzrun run /path/to/vulnerability.json \
  --patch /path/to/fix.patch \
  --work-dir work \
  --timeout 30m
```

不传 `--patch` 用于确认原始漏洞；传入补丁后可检查目标崩溃是否消失。

### 4. 查看结果

每个 case 结束后（包括失败或 Ctrl+C 中断），自动删除 `work/runs/<id>/kernel/` 和
`work/runs/<id>/syzkaller/`，保留输入、日志、报告及共享缓存。再次执行该 case 时会重新构建。

假设漏洞 ID 为 `<id>`：

```bash
cat work/runs/<id>/report.md
cat work/runs/<id>/report.json
less work/runs/<id>/logs/kernel-build.log
less work/runs/<id>/logs/attempt-01/qemu.log
```

主要目录如下：

```text
work/
├── cache/                  # 下载内容、Git mirror、rootfs
└── runs/<id>/
    ├── input/              # 元数据、配置、reproducer、补丁
    ├── kernel/linux/       # Linux 工作树
    ├── syzkaller/src/      # syzkaller 工作树
    ├── logs/               # 构建日志及 attempt-01..03
    ├── report.json
    └── report.md
```

同一漏洞再次运行时会清空本次日志，但保留共享下载和 Git mirror 缓存。不要在生成的 Linux 或 syzkaller 工作树中保存手工修改，程序会重置并清理这些目录。

## 结果与退出码

| 结果 | 退出码 | 含义 |
| --- | ---: | --- |
| `reproduced` | `0` | 捕获到与目标指纹匹配的崩溃 |
| `crashed_other` | `0` | 内核崩溃，但与目标漏洞不匹配 |
| `not_reproduced` | `1` | 所有尝试均未复现目标漏洞 |
| `failed` | `2` | 元数据、下载、构建或运行失败 |

执行失败时生成 `work/runs/<id>/failure.json`。诊断时优先查看同目录下的 `logs/`。

## 运行配置

常用环境变量：

| 变量 | 默认值 | 作用 |
| --- | --- | --- |
| `PLATFORM_QEMU_MEM` | `2048` | QEMU 内存，单位 MB |
| `PLATFORM_QEMU_SMP` | `2` | QEMU vCPU 数量 |
| `PLATFORM_DISABLE_KVM` | 未设置 | 设置后禁用 KVM |
| `PLATFORM_LINUX_REPO` | Linux 官方仓库 | 覆盖 Linux mirror 地址 |
| `PLATFORM_SYZKALLER_REPO` | syzkaller 官方仓库 | 覆盖 syzkaller mirror 地址 |
| `PLATFORM_SYZBOT_BASE_URL` | `https://syzkaller.appspot.com` | 解析 syzbot 相对链接 |
| `PLATFORM_REFRESH_REPOS` | 未设置 | 设为 `1` 时刷新 Git mirror |
| `PLATFORM_GIT_RETRIES` | `3` | Git 网络操作重试次数 |
| `PLATFORM_SYMBOLIZER_TIMEOUT` | `300` | 符号化超时，单位秒 |

## Python API

```python
from pathlib import Path
from syzrun.api import RunOptions, run_vulnerability

result = run_vulnerability(
    RunOptions(
        metadata=Path("vulnerability.json"),
        patch=Path("fix.patch"),  # 不验证补丁时设为 None
        work_dir=Path("work"),
        timeout="30m",
    )
)

print(result.exit_code)
print(result.report_json or result.failure_json)
```
