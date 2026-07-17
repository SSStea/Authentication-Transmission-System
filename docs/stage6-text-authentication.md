# 阶段6文本认证传输

阶段6实现真实的手动文本TESLA广播认证。集中管理GUI为每个选中Sender签发独立材料，
通过可信TCP分别下发Sender配置、Receiver公开上下文和文本载荷，再以统一未来时间控制轮次。
原生TESLA逐包携带MAC；改进TESLA仅在组末携带τ和 `FastGroupTag`。

## 已实现功能

- 文本按UTF-8校验，实际编码长度限制为1至32B，不允许零字节；算法输入始终使用补零后的固定32B Message。
- 原生和改进TESLA共用一套Sender/Receiver运行时、UDP二进制Codec和文本工作负载。
- 集中管理GUI实时校验改进参数；非法输入标红，禁止生成CA材料、下发配置和开始轮次。
- 管理端等待全部配置确认后才允许开始；任一节点拒绝配置时本轮不能启动。
- 开始命令使用统一未来时间；暂停在指定逻辑间隔结束后生效；继续从下一个逻辑间隔和新的统一未来时间恢复。
- PC节点和Linux NodeAgent均可作为Sender或Receiver。Sender节点不配置自己的Receiver上下文，避免自身组播忽略策略被误判为丢包。
- Sender和Receiver通过原TCP连接上报完成、认证失败、披露超时、调度超限或停止结果；管理GUI、PC日志和无人机MONITOR日志显示真实结果。
- Receiver只接受可信来源IP和 `chainId` 的组合，先做固定头快速检查，再把完整解析和密码计算放入工作线程。

## 风险控制

| 风险 | 已实现处理 |
|---|---|
| 跨平台线程生命周期 | Sender线程可停止并在重配、停止和析构时 `join`；Receiver使用一个持久工作线程并在析构时等待退出；不使用 `detach`。 |
| Qt回调线程 | 算法工作线程只把发送任务放入有界队列；Qt主线程通过排队调用分批操作 `QUdpSocket`。结果事件同样排队回Qt线程，停止过程不使用阻塞式跨线程回调。 |
| 高密度发包 | Sender开始前生成全部报文并执行时间预算预检；PC发送队列和Receiver接收队列均限制为8192项，PC每次最多处理256项，队列满时明确失败。 |
| 暂停后的时间基准 | 暂停命令同时指定逻辑间隔和墙钟边界；Sender在该边界进入暂停，Receiver保存同一时间线；继续命令建立新的时间线段。 |
| 时间同步 | Windows PC开始前查询 `w32tm`，Linux NodeAgent查询systemd-timesyncd或Chrony；无法确认同步时拒绝开始。 |
| 调度超限 | Sender使用绝对截止时间发送；任何Socket失败或间隔截止时间越界都会停止本轮并上报 `INVALID_SCHEDULING_OVERRUN`，该轮不得作为算法对比样本。 |
| 解析与内存安全 | UDP固定头按明确顺序读取；完整报文长度由可信上下文推导。阶段6地址/未定义行为检查覆盖原生、改进和暂停恢复路径。 |

## 界面操作

至少启动两个正常广播节点，其中一个可作为Sender，另一个作为Receiver。Windows PC节点运行
`tesla_pc_node_gui`；无人机运行Linux `tesla_node_agent`。然后：

1. 启动 `tesla_manager_gui`，点击“扫描节点”“连接全部”。
2. 在节点表勾选一个或多个Sender。至少还需要一个已连接的其他节点接收组播。
3. 在“参数与载荷”输入文本、发送次数、每间隔发包数、时间间隔和披露延迟。
4. 改进模式下设置分组大小和检测阈值；界面必须显示参数有效。
5. 点击“生成并下发本轮CA材料”，等待状态栏显示全部配置已确认。
6. 在“实验控制”点击“开始”。运行中可使用“暂停”“继续”和“停止”。
7. 管理GUI状态栏、PC节点日志和无人机MONITOR日志会显示轮次结果。Wireshark式逐包展示属于阶段8。

Windows首次监听TCP/UDP时需要允许防火墙访问专用网络。所有节点使用内部固定认证组播
`239.10.10.10:39020`。若开始命令被拒绝，应先确认Windows时间服务或Linux NTP/Chrony状态。

## 自动验收

`tesla_stage6_tests`覆盖：

1. 原生TESLA文本端到端认证；
2. 统一逻辑间隔暂停和未来时间恢复；
3. 改进TESLA快速组认证端到端完成；
4. Sender超过间隔截止时间后上报 `INVALID_SCHEDULING_OVERRUN`；
5. Sender/Receiver停止后工作线程可安全回收。

Windows和Linux Release CTest均必须通过。Linux另使用AddressSanitizer和UndefinedBehaviorSanitizer
运行阶段6测试，检查策略详情生命周期、UDP解析和线程退出路径。
