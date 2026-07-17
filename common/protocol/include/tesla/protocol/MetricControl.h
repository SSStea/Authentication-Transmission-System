#pragma once

#include "tesla/metrics/AuthenticationMetrics.h"

#include <cstdint>
#include <string>
#include <vector>

namespace tesla::protocol
{
/** @brief NodeAgent将高频指标合并成有界批次后发送给MONITOR。 */
class MetricEventControlDetails final
{
public:
    explicit MetricEventControlDetails(
        std::vector<metrics::AuthenticationMetricRecord> vecRecords
    );

    const std::vector<metrics::AuthenticationMetricRecord>& vecRecords() const noexcept;

private:
    std::vector<metrics::AuthenticationMetricRecord> m_vecRecords;
};

/** @brief MONITOR重连时分批恢复NodeAgent仍保留的指标记录。 */
class MetricSnapshotControlDetails final
{
public:
    MetricSnapshotControlDetails(
        std::string strRequestId,
        std::uint32_t u32Sequence,
        bool bFinalBatch,
        std::vector<metrics::AuthenticationMetricRecord> vecRecords
    );

    const std::string& strRequestId() const noexcept;
    std::uint32_t u32Sequence() const noexcept;
    bool bFinalBatch() const noexcept;
    const std::vector<metrics::AuthenticationMetricRecord>& vecRecords() const noexcept;

private:
    std::string                                      m_strRequestId;
    std::uint32_t                                    m_u32Sequence;
    bool                                             m_bFinalBatch;
    std::vector<metrics::AuthenticationMetricRecord> m_vecRecords;
};
}
