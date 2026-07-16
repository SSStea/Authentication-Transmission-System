# Authentication Transmission System

无人机集群 TESLA 广播认证系统的正式开发仓库。

## 仓库登记

- 仓库名称：`Authentication_Transmission_System`
- 绝对路径：`D:\0_Tesla_Authenticication_Protocol\Authentication_Transmission_System`
- Git 远端：`https://github.com/SSStea/Authentication-Transmission-System.git`
- 开发指南：`D:\0_Tesla_Authenticication_Protocol\TESLA_SYSTEM_DEVELOPMENT_GUIDE_DRAFT.md`
- 当前阶段：阶段 4 已完成，等待阶段 5 实施方案确认

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

## 代码组织原则

同一功能模块内，职责、生命周期和变更原因一致的辅助类型放在同一组头文件和实现文件中，
避免为了“一类一文件”产生过多零散文件。当前主要模块文件包括：

- `CryptoTypes`：密码算法枚举和公共二进制类型；
- `KeyChain`：密钥链生成、访问和披露密钥验证；
- `ProtocolTypes`：协议公共二进制类型和结构化解析错误；
- `TcpFrame`：TCP载荷、帧模型、整帧Codec和流式拆帧；
- `NodeDiscoveryMessage`：发现消息模型和UDP JSON编解码；
- `AuthenticationControl`：阶段4认证配置类型、详情和固定十六进制字段编解码；
- `UdpAuthenticationPacket`：UDP认证模式、可信解析上下文和报文模型；
- `AuthenticationRoundParameters`：认证模式、改进参数和一轮公共调度参数；
- `AuthenticationPacketInput`：单包和固定槽位分组的算法输入；
- `NativeTeslaDetails`、`ImprovedTeslaDetails`：各自模式的认证与验证详情；
- `KsRsMatrix`：KS+RS矩阵、位置级结果和回退验证器；
- `TeslaStrategy`：策略接口、模式专用`std::variant`和统一验证结果；
- `SenderAuthenticationContext`、`ReceiverAuthenticationContextStore`：分别维护私有Sender状态和公开Receiver状态。

密码提供者与安全随机源接口、CA、原生/改进策略实现、控制JSON Codec、UDP二进制Codec和
NodeAgent各网络服务继续独立，保留安全边界、策略边界和序列化边界。

阶段 1 提供可构建、可启动的最小程序入口。阶段 2 实现三种密码套件、密钥链、原生/改进TESLA策略、快速组认证和KS+RS回退。阶段 3 实现无Qt公共协议库、Linux POSIX NodeAgent运行时、TCP管理、UDP发现和TESLA组播。阶段 4 实现安全随机源、CA独立材料签发、Sender本地密钥链自检、Receiver公开上下文映射和事务性TCP配置；工作负载、GUI业务和指标仍在后续阶段分别确认后实现。

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

Windows下的 `tesla_node_agent` 是审阅入口，POSIX Socket运行时源码显示在独立的
`tesla_node_agent_runtime` 项目中；正式网络服务只在Linux目标上参与编译和运行。

### Visual Studio 审阅解决方案

使用审阅预设生成一个解决方案，其中业务目标按 `Libraries`、`Applications` 和 `Tests`
分组，CMake内部目标单独放在 `CMake` 分组。每个业务项目都显示对应的头文件、源文件和
`CMakeLists.txt`，无需在仓库目录中逐层查找。

```powershell
cmake --preset windows-vs2022-review `
  -DCMAKE_PREFIX_PATH="C:/Qt/6.10.2/msvc2022_64" `
  -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64"

cmake --build --preset windows-vs2022-review-release
ctest --preset windows-vs2022-review-release
```

生成后打开：

`build/windows-review/AuthenticationTransmissionSystem.sln`

解决方案和`.vcxproj`均为CMake生成文件，保留在已忽略的`build/`目录中，不提交到Git。

## Ubuntu Server 构建

依赖：C++17 编译器、OpenSSL、Threads 和 CMake。Ubuntu Server不需要Qt。配置阶段会按固定版本和SHA-256校验值获取仅用于控制面的nlohmann/json 3.12.0。

```bash
cmake -S . -B build/linux \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_GUI=OFF

cmake --build build/linux -j
ctest --test-dir build/linux --output-on-failure
```

Ubuntu Server构建生成 `tesla_node_agent`。

NodeAgent自动选择活动的非回环IPv4局域网接口，使用内部固定端口和组播地址启动服务，
不要求普通用户填写网卡、IP、端口或组播地址。按 `Ctrl+C` 可安全停止服务。

阶段3至阶段4的协议和联调说明见[网络协议与NodeAgent](docs/network-protocol-and-node-agent.md)。
