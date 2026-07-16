# 网络协议与NodeAgent

阶段3至阶段4采用“JSON控制面 + 二进制文件帧 + 固定二进制认证数据面”。公共协议和Linux NodeAgent均不依赖Qt。

## TCP长度前缀帧

`TcpFrameCodec`对单个完整帧编解码，`TcpFrameStreamDecoder`负责处理TCP分片和粘包：

```text
uint32 frameLength   网络字节序，长度包含frameType和payload
uint8  frameType     0x01 JSON_CONTROL，0x02 FILE_BINARY_CHUNK
byte[] payload
```

JSON载荷必须是一个完整UTF-8对象。文件帧使用 `FileBinaryChunk`，依次携带8B `chainId`、4B `chunkIndex`、4B `dataLength`和原始文件字节。它不复用32B TESLA Message分片。

每条NodeAgent TCP连接的首个控制消息必须是 `CLIENT_HELLO`，角色为 `MANAGER` 或 `MONITOR`。阶段3实现 `PING/PONG` 和 `STATUS_REQUEST/STATUS_RESPONSE`；阶段4增加 `SENDER_AUTH_CONFIG`、`RECEIVER_AUTH_CONTEXTS` 和 `AUTH_CONFIG_ACK`。文件处理在后续阶段接入同一帧格式。

认证控制消息中的任意64位 `chainId` 固定编码为16个十六进制字符，不能使用JSON数字，避免超过双精度安全整数范围后丢失低位。种子和 `K0` 固定编码为64个十六进制字符。Receiver上下文消息没有种子字段。

协议源码按审阅职责组织：

- `ProtocolTypes`保存公共字节类型和解析错误；
- `AttackControl`保存集中管理GUI与攻击测试端之间的独立最小控制消息及JSON Codec；
- `TcpFrame`集中长度前缀帧模型、整帧Codec与流式拆帧；
- `NodeDiscoveryMessage`集中发现消息及其JSON编解码；
- `AuthenticationControl`集中阶段4认证控制参数、模式专用详情和十六进制字段编码；
- `NodeControlMessage`与`NodeControlJsonCodec`继续分离，避免大型控制消息模型与JSON序列化实现过度耦合；
- `UdpAuthenticationPacket`集中UDP模式、可信解析上下文和报文模型，二进制Codec继续独立。

攻击测试端不复用NodeAgent的 `CLIENT_HELLO` 或认证配置消息。阶段5独立攻击控制协议只包含
`ATTACK_CLIENT_HELLO`、`ATTACK_PING/ATTACK_PONG`、
`ATTACK_STATUS_REQUEST/ATTACK_STATUS_RESPONSE` 和 `ATTACK_ERROR`，继续封装在相同的TCP长度前缀JSON控制帧中。
统一的 `ATTACK_` 线缆类型前缀用于隔离协议域；文件帧和普通节点配置消息会被攻击端明确拒绝。

## UDP认证报文

`UdpAuthenticationPacket`使用 `std::variant` 区分数据报文和披露尾包，数据报文内部继续使用原生/改进模式专用详情。没有“所有字段平铺”的统一大结构体。

固定字段顺序为：

```text
chainId[8] | intervalIndex[4] | packetIndex[4]
数据报文: Message[32] | 条件Key[32] | 原生MAC[32]或条件组标签
披露尾包: packetIndex=0 | Key[32]
```

`UdpAuthenticationPacketCodec`依据可信的 `UdpAuthenticationPacketContext` 推导Key、τ和 `FastGroupTag` 是否存在。缺字段、多余字段、间隔不一致、报文编号越界和上下文不匹配均返回 `ProtocolDecodeError`，在密码计算前拒绝。

## NodeAgent服务

Linux目标将网络实现编译到独立的 `tesla_node_agent_runtime` 静态库：

- `NetworkInterfaceSelector`：选择活动的非回环IPv4接口，并按IP末段生成 `UAV-xxx` 名称；
- `TcpManagementServer`：管理 `MANAGER/MONITOR` 持久连接、状态查询和认证配置分发；
- `NodeAuthenticationConfigController`：把控制协议映射为核心认证类型，验证后事务性更新Sender或Receiver状态；
- `UdpDiscoveryService`：响应发现请求并周期发送心跳；
- `UdpMulticastChannel`：加入固定TESLA组播，收发原始认证数据报并忽略自身源IP；
- `NodeAgentService`：按“先加入组播、再开放管理和发现”的顺序统一管理生命周期。

## 阶段4认证材料与上下文

- `OpenSslSecureRandomProvider`只使用OpenSSL系统级安全随机源，失败时不降级到普通伪随机数；
- `AuthenticationAuthority`为不同Sender签发不同的种子、`chainId` 和 `K0`，完整密钥链只作为签发过程中的局部临时对象；
- `SenderAuthenticationMaterial`包含Sender私有种子，`ReceiverAuthenticationContext`只包含来源IP、Sender ID、`chainId`、`K0`和公开调度参数；
- Sender收到配置后重建完整密钥链，并以常量时间比较本地 `K0` 与下发值；
- Receiver先按实际UDP来源IP确定Sender，再以 `senderId + chainId` 查找上下文；
- Sender和Receiver均先构造完整候选配置，全部验证通过后才替换旧状态。错误配置、冲突IP映射和MONITOR越权不会破坏已有配置。

密钥链长度固定按 `ceil(totalPacketCount / packetsPerInterval) + 1` 计算，其中额外的1为 `K0`；披露延迟不增加密钥链长度。

## 阶段3至阶段4验收测试

`tesla_protocol_tests`覆盖TCP帧、流式分帧、JSON消息、原生/改进UDP报文、尾组、披露尾包、错误长度和协议到算法输入映射。

`tesla_node_agent_network_tests`在Linux回环网段启动两个独立NodeAgent实例，由一个PC测试客户端完成：

1. 发送一次UDP广播发现请求并取得两个UAV公告；
2. 分别建立MANAGER TCP连接；
3. 在真实Socket路径制造TCP分片和粘包，验证PONG与状态响应；
4. CA为两个Sender签发彼此不同的材料，并通过真实TCP分别下发Sender配置；
5. 向Receiver一次性下发两个公开上下文，验证来源IP和 `chainId` 映射；
6. 提交篡改 `K0`、冲突IP和MONITOR越权配置，验证拒绝结果及旧状态保留；
7. 由一个NodeAgent组播固定二进制TESLA报文，另一个NodeAgent接收并逐字节比较。
