#pragma once

#include "tesla/protocol/MonitorControl.h"

#include <QWidget>

#include <vector>

namespace tesla::gui
{
/**
 * @brief PC和无人机监控端共用的报文/异常查询组件。
 *
 * 组件只展示运行时产生的真实观测快照，不参与认证、不会重新计算结果，
 * 从而保证筛选和跳转不会改变底层统计。
 */
class AuthenticationMonitorWidget final : public QWidget
{
public:
    explicit AuthenticationMonitorWidget(QWidget* pParent = nullptr);
    ~AuthenticationMonitorWidget() override;

    void setSnapshots(
        std::vector<protocol::PacketObservationControlDetails> vecPackets,
        std::vector<protocol::PacketFailureControlDetails> vecFailures,
        std::vector<protocol::DosSummaryControlDetails> vecDosSummaries
    );

private:
    class Impl;
    Impl* m_pImpl;
};
}
