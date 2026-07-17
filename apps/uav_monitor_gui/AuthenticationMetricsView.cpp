#include "AuthenticationMetricsView.h"

#include <QChart>
#include <QChartView>
#include <QLabel>
#include <QLineSeries>
#include <QPainter>
#include <QString>
#include <QValueAxis>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <variant>

namespace
{
constexpr std::size_t MAX_CHART_POINT_COUNT = 2000;

QString strHardwareStatus(tesla::metrics::HardwareCounterStatus statusCounters)
{
    using tesla::metrics::HardwareCounterStatus;
    switch (statusCounters)
    {
    case HardwareCounterStatus::Supported:
        return QStringLiteral("设备支持");
    case HardwareCounterStatus::NotSupported:
        return QStringLiteral("设备不支持");
    case HardwareCounterStatus::PermissionDenied:
        return QStringLiteral("无读取权限");
    case HardwareCounterStatus::ReadFailed:
        return QStringLiteral("读取失败");
    }

    return QStringLiteral("未知");
}

QWidget* pCreateChartPage(
    QWidget* pParent,
    const QString& strTitle,
    const QString& strHint,
    QLabel*& pSummary,
    QLabel*& pSecondarySummary,
    QChart*& pChart
)
{
    QWidget* pPage = new QWidget(pParent);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    QLabel* pTitle = new QLabel(strTitle, pPage);
    pTitle->setObjectName(QStringLiteral("sectionTitleLabel"));
    QLabel* pHint = new QLabel(strHint, pPage);
    pHint->setWordWrap(true);
    pHint->setObjectName(QStringLiteral("hintLabel"));
    pSummary = new QLabel(QStringLiteral("尚无真实认证指标"), pPage);
    pSummary->setObjectName(QStringLiteral("stateValue"));
    pSecondarySummary = new QLabel(pPage);
    pSecondarySummary->setObjectName(QStringLiteral("hintLabel"));
    pChart = new QChart();
    pChart->setAnimationOptions(QChart::NoAnimation);
    pChart->legend()->setVisible(true);
    QChartView* pChartView = new QChartView(pChart, pPage);
    pChartView->setRenderHint(QPainter::Antialiasing);

    pLayout->addWidget(pTitle);
    pLayout->addWidget(pHint);
    pLayout->addWidget(pSummary);
    pLayout->addWidget(pSecondarySummary);
    pLayout->addWidget(pChartView, 1);
    return pPage;
}
}

AuthenticationMetricsView::AuthenticationMetricsView(QWidget* pParent)
    : m_pComputationPage(nullptr),
      m_pEnergyPage(nullptr),
      m_pComputationSummary(nullptr),
      m_pHardwareSummary(nullptr),
      m_pEnergySummary(nullptr),
      m_pNativeVerifySeries(new QLineSeries()),
      m_pFastVerifySeries(new QLineSeries()),
      m_pFallbackVerifySeries(new QLineSeries()),
      m_pIncompleteVerifySeries(new QLineSeries()),
      m_pNativeEnergySeries(new QLineSeries()),
      m_pFastEnergySeries(new QLineSeries()),
      m_pFallbackEnergySeries(new QLineSeries()),
      m_pIncompleteEnergySeries(new QLineSeries()),
      m_pIneligibleEnergySeries(new QLineSeries()),
      m_pComputationXAxis(new QValueAxis()),
      m_pComputationYAxis(new QValueAxis()),
      m_pEnergyXAxis(new QValueAxis()),
      m_pEnergyYAxis(new QValueAxis())
{
    QChart* pComputationChart = nullptr;
    m_pComputationPage = pCreateChartPage(
        pParent,
        QStringLiteral("计算开销"),
        QStringLiteral(
            "原生TESLA每个点是一包验证；改进TESLA每个点是一组完整验证。"
            "耗时不包含披露等待、GUI刷新、日志和文件Hash。"
        ),
        m_pComputationSummary,
        m_pHardwareSummary,
        pComputationChart
    );
    configureSeries(m_pNativeVerifySeries, QStringLiteral("NATIVE_PACKET_VERIFY"));
    configureSeries(m_pFastVerifySeries, QStringLiteral("FAST_GROUP_PASS"));
    configureSeries(m_pFallbackVerifySeries, QStringLiteral("KS_RS_FALLBACK"));
    configureSeries(m_pIncompleteVerifySeries, QStringLiteral("INCOMPLETE_GROUP_TAGS"));
    pComputationChart->addAxis(m_pComputationXAxis, Qt::AlignBottom);
    pComputationChart->addAxis(m_pComputationYAxis, Qt::AlignLeft);
    for (QLineSeries* pSeries : {
            m_pNativeVerifySeries,
            m_pFastVerifySeries,
            m_pFallbackVerifySeries,
            m_pIncompleteVerifySeries
        })
    {
        pComputationChart->addSeries(pSeries);
        pSeries->attachAxis(m_pComputationXAxis);
        pSeries->attachAxis(m_pComputationYAxis);
    }
    m_pComputationXAxis->setTitleText(QStringLiteral("验证采样序号"));
    m_pComputationYAxis->setTitleText(QStringLiteral("验证耗时 (μs)"));
    m_pComputationXAxis->setLabelFormat(QStringLiteral("%.0f"));

    QChart* pEnergyChart = nullptr;
    QLabel* pEnergyModel = nullptr;
    m_pEnergyPage = pCreateChartPage(
        pParent,
        QStringLiteral("估算验证能耗"),
        QStringLiteral(
            "固定模型：0.181 μJ/μs × 实际验证耗时 + "
            "0.038504 μJ/B × 实际接收算法字段。以下结果不是功率计实测。"
        ),
        m_pEnergySummary,
        pEnergyModel,
        pEnergyChart
    );
    pEnergyModel->setText(QStringLiteral("明确口径：估算能耗，非电池实际消耗"));
    configureSeries(m_pNativeEnergySeries, QStringLiteral("原生TESLA"));
    configureSeries(m_pFastEnergySeries, QStringLiteral("改进 FAST_GROUP_PASS"));
    configureSeries(m_pFallbackEnergySeries, QStringLiteral("改进 KS_RS_FALLBACK"));
    configureSeries(m_pIncompleteEnergySeries, QStringLiteral("改进 INCOMPLETE_GROUP_TAGS"));
    configureSeries(m_pIneligibleEnergySeries, QStringLiteral("其他异常/未完成（不可比）"));
    pEnergyChart->addAxis(m_pEnergyXAxis, Qt::AlignBottom);
    pEnergyChart->addAxis(m_pEnergyYAxis, Qt::AlignLeft);
    for (QLineSeries* pSeries : {
            m_pNativeEnergySeries,
            m_pFastEnergySeries,
            m_pFallbackEnergySeries,
            m_pIncompleteEnergySeries,
            m_pIneligibleEnergySeries
        })
    {
        pEnergyChart->addSeries(pSeries);
        pSeries->attachAxis(m_pEnergyXAxis);
        pSeries->attachAxis(m_pEnergyYAxis);
    }
    m_pEnergyXAxis->setTitleText(QStringLiteral("完整验证轮次"));
    m_pEnergyYAxis->setTitleText(QStringLiteral("估算能耗 (mJ)"));
    m_pEnergyXAxis->setLabelFormat(QStringLiteral("%.0f"));

    updateAxes(m_pComputationXAxis, m_pComputationYAxis, 1.0, 1.0);
    updateAxes(m_pEnergyXAxis, m_pEnergyYAxis, 1.0, 1.0);
}

QWidget* AuthenticationMetricsView::pComputationPage() const noexcept
{
    return m_pComputationPage;
}

QWidget* AuthenticationMetricsView::pEnergyPage() const noexcept
{
    return m_pEnergyPage;
}

void AuthenticationMetricsView::setRecords(
    const std::vector<tesla::metrics::AuthenticationMetricRecord>& vecRecords
)
{
    using namespace tesla::metrics;
    for (QLineSeries* pSeries : {
            m_pNativeVerifySeries,
            m_pFastVerifySeries,
            m_pFallbackVerifySeries,
            m_pIncompleteVerifySeries,
            m_pNativeEnergySeries,
            m_pFastEnergySeries,
            m_pFallbackEnergySeries,
            m_pIncompleteEnergySeries,
            m_pIneligibleEnergySeries
        })
    {
        pSeries->clear();
    }

    const std::size_t nVerificationCount = static_cast<std::size_t>(std::count_if(
        vecRecords.begin(),
        vecRecords.end(),
        [](const AuthenticationMetricRecord& varRecord)
        {
            return std::holds_alternative<VerificationMetricSample>(varRecord);
        }
    ));
    const std::size_t nEnergyCount = static_cast<std::size_t>(std::count_if(
        vecRecords.begin(),
        vecRecords.end(),
        [](const AuthenticationMetricRecord& varRecord)
        {
            return std::holds_alternative<EstimatedEnergyMetricSummary>(varRecord);
        }
    ));
    const std::size_t nVerificationSkip = nVerificationCount > MAX_CHART_POINT_COUNT
        ? nVerificationCount - MAX_CHART_POINT_COUNT
        : 0;
    const std::size_t nEnergySkip = nEnergyCount > MAX_CHART_POINT_COUNT
        ? nEnergyCount - MAX_CHART_POINT_COUNT
        : 0;

    std::size_t nVerificationSeen = 0;
    std::size_t nEnergySeen = 0;
    qreal dVerificationX = 0.0;
    qreal dEnergyX = 0.0;
    qreal dMaximumVerifyTime = 0.0;
    qreal dMaximumEnergy = 0.0;
    const VerificationMetricSample* pLatestSample = nullptr;
    const EstimatedEnergyMetricSummary* pLatestEnergy = nullptr;

    for (const AuthenticationMetricRecord& varRecord : vecRecords)
    {
        if (const auto* pSample = std::get_if<VerificationMetricSample>(
                &varRecord
            ))
        {
            ++nVerificationSeen;
            if (nVerificationSeen <= nVerificationSkip)
            {
                continue;
            }

            ++dVerificationX;
            const qreal dVerifyTimeMicroseconds = static_cast<qreal>(
                pSample->mstPerformance().u64DurationNanoseconds()
            ) / 1000.0;
            QLineSeries* pTargetSeries = m_pNativeVerifySeries;
            switch (pSample->pathVerification())
            {
            case VerificationMetricPath::NativePacketVerify:
                pTargetSeries = m_pNativeVerifySeries;
                break;
            case VerificationMetricPath::FastGroupPass:
                pTargetSeries = m_pFastVerifySeries;
                break;
            case VerificationMetricPath::KsRsFallback:
                pTargetSeries = m_pFallbackVerifySeries;
                break;
            case VerificationMetricPath::IncompleteGroupTags:
                pTargetSeries = m_pIncompleteVerifySeries;
                break;
            }
            pTargetSeries->append(dVerificationX, dVerifyTimeMicroseconds);
            dMaximumVerifyTime = std::max(dMaximumVerifyTime, dVerifyTimeMicroseconds);
            pLatestSample = pSample;
            continue;
        }

        const auto* pEnergy = std::get_if<EstimatedEnergyMetricSummary>(
            &varRecord
        );
        if (pEnergy == nullptr)
        {
            continue;
        }

        ++nEnergySeen;
        if (nEnergySeen <= nEnergySkip)
        {
            continue;
        }

        ++dEnergyX;
        const qreal dEnergyMilliJoule = pEnergy->dEstimatedEnergyMilliJoule();
        QLineSeries* pTargetSeries = pEnergy->bNormalComparisonEligible()
            ? m_pNativeEnergySeries
            : m_pIneligibleEnergySeries;
        if (const auto* pImproved = std::get_if<ImprovedRoundMetricDetails>(
                &pEnergy->varDetails()
            ))
        {
            if (pImproved->u32IncompleteGroupCount() > 0)
            {
                pTargetSeries = m_pIncompleteEnergySeries;
            }
            else if (pImproved->u32FallbackGroupCount() > 0)
            {
                pTargetSeries = m_pFallbackEnergySeries;
            }
            else if (pEnergy->bNormalComparisonEligible())
            {
                pTargetSeries = m_pFastEnergySeries;
            }
        }
        pTargetSeries->append(dEnergyX, dEnergyMilliJoule);
        dMaximumEnergy = std::max(dMaximumEnergy, dEnergyMilliJoule);
        pLatestEnergy = pEnergy;
    }

    if (pLatestSample == nullptr)
    {
        m_pComputationSummary->setText(QStringLiteral("尚无真实认证指标"));
        m_pHardwareSummary->setText(QStringLiteral("Cache指标：等待设备采样"));
    }
    else
    {
        m_pComputationSummary->setText(
            QStringLiteral("最新验证耗时：%1 μs；平均每包：%2 μs")
                .arg(
                    static_cast<double>(
                        pLatestSample->mstPerformance().u64DurationNanoseconds()
                    ) / 1000.0,
                    0,
                    'f',
                    3
                )
                .arg(
                    pLatestSample->dAveragePacketVerifyTimeMicroseconds(),
                    0,
                    'f',
                    3
                )
        );
        const HardwarePerformanceCounters& ctrHardware =
            pLatestSample->mstPerformance().ctrHardware();
        if (ctrHardware.statusCounters() == HardwareCounterStatus::Supported)
        {
            m_pHardwareSummary->setText(
                QStringLiteral(
                    "CPU cycles=%1；Cache References=%2；Cache Misses=%3；"
                    "命中率=%4%"
                )
                    .arg(ctrHardware.u64CpuCycles())
                    .arg(ctrHardware.u64CacheReferences())
                    .arg(ctrHardware.u64CacheMisses())
                    .arg(ctrHardware.dCacheHitRate() * 100.0, 0, 'f', 2)
            );
        }
        else
        {
            m_pHardwareSummary->setText(
                QStringLiteral("Cache指标：%1；验证耗时仍为真实采样")
                    .arg(strHardwareStatus(ctrHardware.statusCounters()))
            );
        }
    }

    if (pLatestEnergy == nullptr)
    {
        m_pEnergySummary->setText(QStringLiteral("尚无完整轮次估算能耗"));
    }
    else
    {
        m_pEnergySummary->setText(
            QStringLiteral(
                "最新估算能耗：%1 mJ；平均每包：%2 μJ；"
                "验证耗时=%3 μs；接收算法字段=%4B；正常对比=%5"
            )
                .arg(pLatestEnergy->dEstimatedEnergyMilliJoule(), 0, 'f', 6)
                .arg(pLatestEnergy->dAveragePacketEnergyMicroJoule(), 0, 'f', 6)
                .arg(
                    static_cast<double>(pLatestEnergy->u64VerifyTimeNanoseconds())
                        / 1000.0,
                    0,
                    'f',
                    3
                )
                .arg(pLatestEnergy->u64ReceivedAuthBytes())
                .arg(
                    pLatestEnergy->bNormalComparisonEligible()
                        ? QStringLiteral("是")
                        : QStringLiteral("否")
                )
        );
    }

    updateAxes(
        m_pComputationXAxis,
        m_pComputationYAxis,
        dVerificationX,
        dMaximumVerifyTime
    );
    updateAxes(m_pEnergyXAxis, m_pEnergyYAxis, dEnergyX, dMaximumEnergy);
}

void AuthenticationMetricsView::configureSeries(
    QLineSeries* pSeries,
    const QString& strName
)
{
    pSeries->setName(strName);
    pSeries->setPointsVisible(true);
    pSeries->setMarkerSize(5.0);
}

void AuthenticationMetricsView::updateAxes(
    QValueAxis* pXAxis,
    QValueAxis* pYAxis,
    qreal dMaximumX,
    qreal dMaximumY
)
{
    pXAxis->setRange(0.0, std::max<qreal>(1.0, dMaximumX + 1.0));
    pYAxis->setRange(0.0, std::max<qreal>(1.0, dMaximumY * 1.10));
}
