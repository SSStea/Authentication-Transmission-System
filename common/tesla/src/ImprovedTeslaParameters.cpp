#include "tesla/core/ImprovedTeslaParameters.h"

#include "tesla/core/KsRsMatrix.h"

namespace tesla::core
{
ImprovedTeslaParameters::ImprovedTeslaParameters(
    std::uint32_t u32GroupSize,
    std::uint32_t u32DetectionThreshold
)
    : m_u32GroupSize(u32GroupSize),
      m_u32DetectionThreshold(u32DetectionThreshold),
      m_nTauCount(
          KsRsMatrix(
              static_cast<std::size_t>(u32GroupSize),
              static_cast<std::size_t>(u32DetectionThreshold)
          ).nRowCount()
      )
{
}

std::uint32_t ImprovedTeslaParameters::u32GroupSize() const noexcept
{
    return m_u32GroupSize;
}

std::uint32_t ImprovedTeslaParameters::u32DetectionThreshold() const noexcept
{
    return m_u32DetectionThreshold;
}

std::size_t ImprovedTeslaParameters::nTauCount() const noexcept
{
    return m_nTauCount;
}
}
