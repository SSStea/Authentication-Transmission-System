# 阶段8：报文、异常与本地可视化

阶段8的观测数据来自Sender/Receiver实际运行路径，不创建GUI模拟报文，也不在界面中重新执行认证。算法运行时以`AuthenticationObservation`的`std::variant`传递报文、失败、改进分组和DoS汇总四类事件；报文内部继续用DATA/DISCLOSE及原生/改进模式专用详情，避免所有字段平铺。

## 数据保留与线程边界

- `AuthenticationObservationStore`使用5000条普通报文环形缓存、2000条异常上限、512条分组上限和120个DoS窗口上限。
- 失败记录共享引用对应报文，因此普通环形缓存淘汰后，当前轮次和最近完成轮次的异常详情仍可查看。
- 异常达到上限后只继续累计分类计数，并生成一次`ABNORMAL_RECORD_LIMIT_REACHED`；相同`eventId`的实时事件和重连快照采用更新语义。
- PC运行时回调只向Qt主线程排队一个合并刷新通知；NodeAgent使用4096项有界队列和独立广播线程，慢MONITOR连接具有200ms发送超时，不阻塞认证线程。
- Receiver每1000ms汇总无效流量；每个窗口只为前16个低频协议/上下文错误保留结构化详情，其余计入限速汇总。

## MONITOR协议

NodeAgent只把高频观测事件发给完成握手的`MONITOR`客户端。无人机监控端连接后发送`ABNORMAL_EVENT_SNAPSHOT_REQUEST`，服务端分批返回失败事件及其引用的完整报文，确保短暂断线后仍能查看Message、认证字段和原始UDP字节。PC完整密钥链使用独立的本地类型和回调，永不进入NodeControl协议。

## GUI能力

PC和无人机GUI复用`AuthenticationMonitorWidget`：

- 报文表使用`QAbstractTableModel`，支持全部、仅看异常、MAC、快速组、τ、重放、协议错误和丢失快捷筛选；
- 支持Sender、Chain ID、报文编号、间隔编号、实际源IP和结果状态组合查询；
- 详情显示逻辑/实际来源、上下文、完整Message、MAC/τ/`FastGroupTag`、披露Key、候选Hash及原始UDP字节；
- 异常记录独立显示，双击后清除冲突筛选并跳转到对应候选；缺失报文显示只读预期槽位，不伪造载荷。

PC额外提供本地完整密钥链状态表和改进TESLA定位步骤表。快速组通过时明确显示“不进入矩阵定位”，只有KS+RS回退记录展示实际排除好包的行扫描过程。无人机GUI不接收密钥链，也不展示矩阵过程，只显示失败事件中的最终坏包编号。

## 验收

`tesla_stage8_tests`覆盖异常快照JSON往返、原始UDP字节保持、普通缓存淘汰后的异常详情、快照事件去重、异常上限唯一告警、轮次保留和KS+RS实际定位轨迹。Windows构建两套GUI；Linux/WSL构建NodeAgent及无Qt测试目标。
