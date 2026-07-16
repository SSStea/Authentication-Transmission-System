# Authentication Transmission System

无人机集群 TESLA 广播认证系统的正式开发仓库。

## 仓库登记

- 仓库名称：`Authentication_Transmission_System`
- 绝对路径：`D:\0_Tesla_Authenticication_Protocol\Authentication_Transmission_System`
- Git 远端：`https://github.com/SSStea/Authentication-Transmission-System.git`
- 开发指南：`D:\0_Tesla_Authenticication_Protocol\TESLA_SYSTEM_DEVELOPMENT_GUIDE_DRAFT.md`
- 当前阶段：阶段 1，目录和顶层 CMake 骨架

旧仓库只作为已验证逻辑的阅读来源，不作为本仓库的子模块，也不得整体复制旧工程。

## 目标结构

```text
common/
├── protocol/
├── crypto/
├── tesla/
├── workload/
└── metrics/

apps/
├── manager_gui/
├── pc_node_gui/
├── uav_monitor_gui/
├── attack_test_gui/
└── node_agent/

tests/
├── protocol_tests/
├── crypto_tests/
├── tesla_tests/
└── integration_tests/
```

阶段 1 只提供可构建、可启动的最小程序入口。TESLA、协议、密码、工作负载和指标业务逻辑将在后续阶段分别确认后实现。

## Windows 构建

依赖：Visual Studio 2022、Qt 6、OpenSSL 和 CMake。

```powershell
cmake -S . -B build/windows `
  -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_PREFIX_PATH="C:/Qt/6.10.2/msvc2022_64" `
  -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64"

cmake --build build/windows --config Release
```

Windows 构建生成：

- `tesla_manager_gui`
- `tesla_pc_node_gui`
- `tesla_uav_monitor_gui`
- `tesla_attack_test_gui`
- `tesla_node_agent`

## Ubuntu Server 构建

依赖：C++17 编译器、OpenSSL、Threads 和 CMake。Ubuntu Server不需要Qt。

```bash
cmake -S . -B build/linux \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_GUI=OFF

cmake --build build/linux -j
```

Ubuntu Server构建生成 `tesla_node_agent`。
