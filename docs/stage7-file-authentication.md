# 阶段7：文件认证、恢复与Hash比较

## 已实现范围

阶段7在阶段6真实TESLA发送与验证运行时上增加文件载荷，不新增文件专用UDP报文。管理端选择完整文件后自动显示文件类型、大小、固定32B Message、分片数、数据间隔数、链长度、预计发送/认证时长和原始SHA-256。

文件大小限制为1至6,400,000B，即最多200,000个32B Message。图片、音频和短视频统一按不透明二进制文件处理，不实现流媒体播放或帧同步。

## 类型和安全边界

- `FileWorkload`只保存已完整接收并通过长度校验的文件字节，负责32B补零切片和按原始长度恢复。
- `FileUploadSession`只处理MANAGER TCP上传事务，校验requestId、chainId、从1开始连续递增的分块编号、64KiB单块上限、声明大小和结束计数。
- `FileBinaryChunk`是TCP传输类型，`FileWorkload::Message`是载荷切片类型，`AuthenticationPacketInput`是算法输入，`UdpAuthenticationPacket`是UDP协议类型；这些类型不互相复用。
- 统一认证结果使用`std::variant`保存文本、文件Sender或文件Receiver专用详情，不使用包含所有模式字段的平铺结构体。
- Receiver只收到文件原始字节数，用它计算固定槽位和删除尾部补零；原始文件和原始SHA-256只保留在集中管理端。

## 传输和恢复流程

1. 管理端向Sender下发CA配置和`FILE_UPLOAD_BEGIN`。
2. 文件主体通过同一MANAGER TCP连接的`FILE_BINARY_CHUNK`二进制帧传输，管理端以64KiB分块并将Qt待写缓存限制在256KiB以内。
3. `FILE_UPLOAD_END`的chainId、分块数和总字节数全部匹配后，Sender才构造`FileWorkload`并预生成TESLA报文。
4. PC节点在可停止、可等待的后台线程准备文件报文，结果通过Qt排队调用返回主线程；NodeAgent在独立TCP客户端工作线程中准备，不阻塞其他连接。
5. Receiver使用`packetIndex`对应的固定槽位保存Message，只有全部槽位认证通过且不存在协议不完整状态时才重组。
6. 最后一个Message按原始字节数删除零填充，恢复文件Hash固定使用SHA-256，不跟随TESLA密码套件变化。
7. 节点先原子落盘恢复文件，再通过TCP返回恢复大小和SHA-256。落盘失败会把结果降级为`PROTOCOL_INCOMPLETE`。
8. 管理端以自己保留的原文件大小和SHA-256执行单次比较，只有状态完成、大小相等和Hash相等才显示“一致”。

Linux NodeAgent默认保存到当前工作目录的`recovered_files/`。PC节点使用Qt应用数据目录下的`recovered_files/`，界面文件页会显示实际目录。

## 风险控制

- 文件内存、分片数、TCP单块和Qt Socket待写量均有硬上限，拒绝无界缓存。
- 上传只允许MANAGER角色；MONITOR不能开始上传或发送二进制分块。
- 断连、乱序、重复开始、requestId/chainId不一致、非64KiB中间分块和结束计数不一致都会终止当前上传状态。
- 配置等待期间任一参与节点断开时，管理端立即取消本轮配置等待，不会永久等待已经不可能返回的ACK。
- 新Sender CA配置会立即清除上一轮已预生成载荷，必须收到同一chainId的新文件后才能开始。
- Receiver不会压缩或重排缺失槽位，存在缺失、认证失败或不完整聚合标签时不会恢复成功。
- 工作线程不使用`detach`；PC停止服务时先等待文件准备线程，再停止公共认证运行时，避免对象生命周期穿透。
- NodeAgent使用临时文件写完后重命名，PC使用`QSaveFile`提交，防止失败时留下被误认为成功的半文件。

## 自动化验收

`tesla_stage7_tests`覆盖：

- 1B、31B、32B、33B、320,000B和6,400,000B文件的切片、补零和逐字节恢复；
- 64KiB TCP分块、连续编号、乱序和超长分块拒绝；
- Receiver配置不包含原始SHA-256，恶意添加该字段时JSON解码拒绝；
- 原生TESLA + SHA-256文件端到端恢复；
- 改进TESLA + SM3认证，同时确认文件完整性Hash仍为SHA-256；
- SHA3-256认证下模拟原子落盘失败，确认结果降级为协议不完整。

Windows审阅构建的全部6个测试目标已经通过。阶段7最终设备验收还需要在PC和至少两个节点之间选择一张非32B整数倍的真实图片，确认各Receiver恢复文件逐字节相等、大小一致且SHA-256一致。
