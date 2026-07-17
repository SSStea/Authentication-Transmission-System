#include "tesla/protocol/MetricControl.h"

#include <stdexcept>
#include <utility>

namespace tesla::protocol
{
namespace
{
constexpr std::size_t MAX_METRIC_BATCH_SIZE = 64;
}

MetricEventControlDetails::MetricEventControlDetails(
    std::vector<metrics::AuthenticationMetricRecord> vecRecords
)
    : m_vecRecords(std::move(vecRecords))
{
    if (m_vecRecords.empty() || m_vecRecords.size() > MAX_METRIC_BATCH_SIZE)
    {
        throw std::invalid_argument("Metric event batch size is invalid");
    }
}

const std::vector<metrics::AuthenticationMetricRecord>&
MetricEventControlDetails::vecRecords() const noexcept
{
    return m_vecRecords;
}

MetricSnapshotControlDetails::MetricSnapshotControlDetails(
    std::string strRequestId,
    std::uint32_t u32Sequence,
    bool bFinalBatch,
    std::vector<metrics::AuthenticationMetricRecord> vecRecords
)
    : m_strRequestId(std::move(strRequestId)),
      m_u32Sequence(u32Sequence),
      m_bFinalBatch(bFinalBatch),
      m_vecRecords(std::move(vecRecords))
{
    if (m_strRequestId.empty()
        || m_u32Sequence == 0
        || m_vecRecords.size() > MAX_METRIC_BATCH_SIZE)
    {
        throw std::invalid_argument("Metric snapshot batch is invalid");
    }
}

const std::string& MetricSnapshotControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

std::uint32_t MetricSnapshotControlDetails::u32Sequence() const noexcept
{
    return m_u32Sequence;
}

bool MetricSnapshotControlDetails::bFinalBatch() const noexcept
{
    return m_bFinalBatch;
}

const std::vector<metrics::AuthenticationMetricRecord>&
MetricSnapshotControlDetails::vecRecords() const noexcept
{
    return m_vecRecords;
}
}
