# syzrun

`syzrun` 是面向 Ubuntu 的 Linux 内核漏洞复现工具。它读取单个 syzbot 风格的漏洞元数据，自动下载复现材料、构建指定版本的 Linux 与 syzkaller、启动 QEMU 执行 reproducer，并输出 JSON 和 Markdown 报告。

当前支持 `amd64`/`x86_64` 和 syz reproducer。每个漏洞只执行一次复现，不会重试；结果以 `reproduced`、`not_reproduced`、`crash_other` 或 `error` verdict 输出。元数据内的补丁不会自动应用，验证补丁时必须显式传入 `--patch`。

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

各 rootfs 的独立构建脚本及设备隔离库位于 `scripts/rootfs/`，也可直接执行其中对应的构建脚本。
所有镜像及 SSH 密钥统一保存在 `work/cache/rootfs/<镜像名称>/`；基础镜像名为 `rootfs-base`，可用 `./scripts/start.sh rootfs-base` 单独构建。

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

默认启用 KVM。确认当前用户可访问 `/dev/kvm`；若无 KVM，可使用较慢的软件虚拟化：

```bash
export PLATFORM_DISABLE_KVM=1
```

## 操作指南

### 1. 复现漏洞

所有 case 的内核均使用容器构建；必须配置构建镜像。第一版 Ubuntu 18.04 镜像保留在 `containers/kernel-build-v1`，用于需要旧用户态的内核。默认使用第二版镜像，基于 Ubuntu 24.04 LTS：

```bash
# 给当前用户配置 Docker 和 KVM 权限
sudo usermod -aG docker,kvm "$USER"
# 退出 SSH，然后重新连接服务器，使组权限生效
exit
```

重新连接后执行：

```bash
conda activate platform

# 确认 Docker 可用
docker info

# v1、v2 镜像都需要被构建
docker build -t syzrun-kernel-build:v1 containers/kernel-build-v1
docker build -t syzrun-kernel-build:v2 containers/kernel-build-v2

cp .env.example .env
# 在 .env 中配置 PLATFORM_KERNEL_BUILD_IMAGE=syzrun-kernel-build:v2
```

批量或单条运行漏洞复现:

```bash
# 全部漏洞
./run_all.sh

# 指定多个漏洞
./run_part.sh

# 单条漏洞
syzrun run /path/to/vulnerability.json --work-dir work --timeout 30m
```

参数说明：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `metadata` | 必填 | 漏洞元数据 JSON |
| `--work-dir` | `work` | 缓存、构建、日志和报告目录 |
| `--timeout` | `30m` | 长耗时步骤上限；支持 `600`、`30m`、`2h`、`1d` |
| `--patch` | 无 | 构建内核前应用的外部补丁 |

### 2. 验证补丁

```bash
syzrun run /path/to/vulnerability.json \
  --patch /path/to/fix.patch \
  --work-dir work \
  --timeout 30m
```

不传 `--patch` 用于确认原始漏洞；传入补丁后可检查目标崩溃是否消失。

### 3. 查看结果

每个 case 结束后（包括失败或 Ctrl+C 中断），自动删除 `work/runs/<id>/kernel/` 和
`work/runs/<id>/syzkaller/`，保留输入、日志、报告及共享缓存。再次执行该 case 时会重新构建。

主要目录如下：

```text
work/
├── cache/                  # 下载内容、Git mirror、rootfs
│   └── rootfs/
│       ├── rootfs-base/     # 默认基础镜像和 SSH 密钥
│       ├── rootfs-evdev3/   # 专用镜像和 SSH 密钥
│       └── ...
└── runs/<id>/
    ├── input/              # 元数据、配置、reproducer、补丁
    ├── kernel/linux/       # Linux 工作树
    ├── syzkaller/src/      # syzkaller 工作树
    ├── logs/               # 构建日志
    ├── report.json
    └── report.md
```

同一漏洞再次运行时会清空本次日志，但保留共享下载和 Git mirror 缓存。不要在生成的 Linux 或 syzkaller 工作树中保存手工修改，程序会重置并清理这些目录。

## 结果与退出码

| 结果 | 退出码 | 含义 |
| --- | ---: | --- |
| `reproduced` | `0` | 捕获到与目标指纹匹配的崩溃 |
| `not_reproduced` | `1` | 唯一一次复现未发现内核崩溃，或 `syz-execprog` 超时 |
| `crash_other` | `1` | 发现内核崩溃，但原始或符号化后的指纹不匹配目标 |
| `error` | `2` | 复现基础设施或执行过程发生异常 |

终端只有完整行 `verdict: reproduced` 表示成功。`not_reproduced`、`crash_other` 和 `error` 都表示此次复现未成功；诊断时优先查看同目录下的 `logs/`。元数据、下载、构建或启动阶段发生异常时还会生成 `work/runs/<id>/failure.json`。

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
