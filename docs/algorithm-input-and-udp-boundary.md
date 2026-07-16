# 算法输入与UDP报文类型边界

密码算法输入编码和UDP认证报文序列化属于两个不同层次，禁止共用同一数据类型或编解码类。

## 阶段2：算法域

算法域位于 `common/tesla`：

- `AuthenticationPacketInput`：MAC计算所需的逻辑Sender、认证轮次、间隔、报文编号和固定32B Message。
- `AuthenticationGroupInput`：快速组认证和KS+RS回退使用的固定报文槽位及可信上下文。
- `AuthenticationInputEncoder`：只生成MAC输入和 `FastGroupTag` 输入的唯一二进制字节序列。

这些类型不描述UDP字段是否存在，不解析网络数据报，也不保存原始UDP负载。

## 阶段3：协议域

阶段3必须在 `common/protocol` 中建立独立类型和类：

- `UdpAuthenticationPacket`：表示第14章固定UDP认证报文中的实际字段及条件字段。
- `UdpAuthenticationPacketCodec`：负责网络字节序、长度检查和UDP负载编解码。
- 显式适配逻辑：在协议解析及上下文检查成功后，将UDP报文和可信Receiver上下文转换为算法域输入。

`UdpAuthenticationPacket`不得继承、别名或直接复用 `AuthenticationPacketInput`；`UdpAuthenticationPacketCodec`不得调用 `AuthenticationInputEncoder`代替UDP序列化。反向发送时也必须先由策略生成模式专用认证详情，再由协议Codec决定实际携带字段。
