#pragma once

#include "tesla/metrics/AuthenticationMetrics.h"

#include <QtGlobal>

#include <vector>

class QLabel;
class QLineSeries;
class QString;
class QValueAxis;
class QWidget;

/** @brief 共同维护无人机计算开销和估算能耗两个关联图表页面。 */
class AuthenticationMetricsView final
{
public:
    explicit AuthenticationMetricsView(QWidget* pParent);

    QWidget* pComputationPage() const noexcept;
    QWidget* pEnergyPage() const noexcept;
    void setRecords(
        const std::vector<tesla::metrics::AuthenticationMetricRecord>& vecRecords
    );

private:
    static void configureSeries(QLineSeries* pSeries, const QString& strName);
    static void updateAxes(
        QValueAxis* pXAxis,
        QValueAxis* pYAxis,
        qreal dMaximumX,
        qreal dMaximumY
    );
    /** @brief 导出当前监视端保留的真实指标记录，便于离线复核。 */
    void exportRecords(bool bJson) const;

    QWidget*     m_pComputationPage;
    QWidget*     m_pEnergyPage;
    QLabel*      m_pComputationSummary;
    QLabel*      m_pHardwareSummary;
    QLabel*      m_pEnergySummary;
    QLineSeries* m_pNativeVerifySeries;
    QLineSeries* m_pFastVerifySeries;
    QLineSeries* m_pFallbackVerifySeries;
    QLineSeries* m_pIncompleteVerifySeries;
    QLineSeries* m_pNativeEnergySeries;
    QLineSeries* m_pFastEnergySeries;
    QLineSeries* m_pFallbackEnergySeries;
    QLineSeries* m_pIncompleteEnergySeries;
    QLineSeries* m_pIneligibleEnergySeries;
    QValueAxis*  m_pComputationXAxis;
    QValueAxis*  m_pComputationYAxis;
    QValueAxis*  m_pEnergyXAxis;
    QValueAxis*  m_pEnergyYAxis;
    std::vector<tesla::metrics::AuthenticationMetricRecord> m_vecRecords;
};
