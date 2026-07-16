# 网络协议与NodeAgent

阶段3采用“JSON控制面 + 二进制文件帧 + 固定二进制认证数据面”。公共协议和Linux NodeAgent均不依赖Qt。

## TCP长度前缀帧

`TcpFrameCodec`对单个完整帧编解码，`TcpFrameStreamDecoder`负责处理TCP分片和粘包：

```text
uint32 frameLength   网络字节序，长度包含frameType和payload
uint8  frameType     0x01 JSON_CONTROL，0x02 FILE_BINARY_CHUNK
byte[] payload
```

JSON载荷必须是一个完整UTF-8对象。文件帧使用 `FileBinaryChunk`，依次携带8B `chainId`、4B `chunkIndex`、4B `dataLength`和原始文件字节。它不复用32B TESLA Message分片。

每条NodeAgent TCP连接的首个控制消息必须是 `CLIENT_HELLO`，角色为 `MANAGER` 或 `MONITOR`。阶段3实现 `PING/PONG` 和 `STATUS_REQUEST/STATUS_RESPONSE`；后续配置和文件处理在对应阶段接入同一帧格式。

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
- `TcpManagementServer`：管理 `MANAGER/MONITOR` 持久连接和状态查询；
- `UdpDiscoveryService`：响应发现请求并周期发送心跳；
- `UdpMulticastChannel`：加入固定TESLA组播，收发原始认证数据报并忽略自身源IP；
- `NodeAgentService`：按“先加入组播、再开放管理和发现”的顺序统一管理生命周期。

## 阶段3验收测试

`tesla_protocol_tests`覆盖TCP帧、流式分帧、JSON消息、原生/改进UDP报文、尾组、披露尾包、错误长度和协议到算法输入映射。

`tesla_node_agent_network_tests`在Linux回环网段启动两个独立NodeAgent实例，由一个PC测试客户端完成：

1. 发送一次UDP广播发现请求并取得两个UAV公告；
2. 分别建立MANAGER TCP连接；
3. 在真实Socket路径制造TCP分片和粘包，验证PONG与状态响应；
4. 由一个NodeAgent组播固定二进制TESLA报文，另一个NodeAgent接收并逐字节比较。

该测试只验证阶段3网络基础设施，不提前实现阶段4的CA上下文分配或后续Sender/Receiver认证状态机。
