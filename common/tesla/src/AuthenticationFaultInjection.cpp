#include "tesla/core/AuthenticationFaultInjection.h"

#include "tesla/protocol/UdpAuthenticationPacketCodec.h"

#include <algorithm>
#include <cmath>
#include <optional>
#include <random>
#include <set>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace tesla::core
{
namespace
{
class FaultPolicyBase : public AuthenticationFaultPolicy
{
public:
    FaultPolicyBase(
        AuthenticationRoundParameters prmRound,
        std::uint32_t u32ProtectedGroupSize
    )
        : m_prmRound(std::move(prmRound)),
          m_u32ProtectedGroupSize(u32ProtectedGroupSize)
    {
        if (m_u32ProtectedGroupSize == 0
            || m_u32ProtectedGroupSize > m_prmRound.u32PacketsPerInterval())
        {
            throw std::invalid_argument(
                "Fault protected group size is outside the sender interval"
            );
        }
    }

protected:
    std::optional<std::uint32_t> optPacketIndex(
        const protocol::ByteBuffer& vecDatagram
    ) const
    {
        const protocol::UdpAuthenticationPacketHeaderDecodeResult resHeader =
            protocol::UdpAuthenticationPacketCodec::resDecodeHeader(vecDatagram);
        if (!std::holds_alternative<protocol::UdpAuthenticationPacketHeader>(
                resHeader
            ))
        {
            return std::nullopt;
        }

        const std::uint32_t u32PacketIndex = std::get<
            protocol::UdpAuthenticationPacketHeader
        >(resHeader).u32PacketIndex();
        return u32PacketIndex == 0
            ? std::nullopt
            : std::optional<std::uint32_t>(u32PacketIndex);
    }

    bool bIsProtectedGroupEnd(std::uint32_t u32PacketIndex) const noexcept
    {
        const std::uint32_t u32PacketsPerInterval =
            m_prmRound.u32PacketsPerInterval();
        const std::uint32_t u32IntervalIndex =
            ((u32PacketIndex - 1U) / u32PacketsPerInterval) + 1U;
        const std::uint32_t u32IntervalFirst =
            (u32IntervalIndex - 1U) * u32PacketsPerInterval + 1U;
        const std::uint32_t u32IntervalLast = std::min(
            m_prmRound.u32TotalPacketCount(),
            u32IntervalIndex * u32PacketsPerInterval
        );
        const std::uint32_t u32GroupOffset =
            (u32PacketIndex - u32IntervalFirst) / m_u32ProtectedGroupSize;
        const std::uint32_t u32GroupEnd = std::min(
            u32IntervalLast,
            u32IntervalFirst
                + (u32GroupOffset + 1U) * m_u32ProtectedGroupSize - 1U
        );
        return u32PacketIndex == u32GroupEnd;
    }

    const AuthenticationRoundParameters& prmRound() const noexcept
    {
        return m_prmRound;
    }

private:
    AuthenticationRoundParameters m_prmRound;
    std::uint32_t                 m_u32ProtectedGroupSize;
};

class PacketLossFaultPolicy final : public FaultPolicyBase
{
public:
    PacketLossFaultPolicy(
        const protocol::PacketLossFaultDetails& detLoss,
        const AuthenticationRoundParameters& prmRound
    )
        : FaultPolicyBase(prmRound, detLoss.u32ProtectedGroupSize())
    {
        std::vector<std::uint32_t> vecEligibleIndexes;
        for (std::uint32_t u32PacketIndex = 1;
             u32PacketIndex <= prmRound.u32TotalPacketCount();
             ++u32PacketIndex)
        {
            if (!bIsProtectedGroupEnd(u32PacketIndex))
            {
                vecEligibleIndexes.push_back(u32PacketIndex);
            }
        }

        std::mt19937_64 rngIndexes(detLoss.u64RandomSeed());
        std::shuffle(
            vecEligibleIndexes.begin(),
            vecEligibleIndexes.end(),
            rngIndexes
        );
        const std::size_t nDropCount = static_cast<std::size_t>(std::llround(
            detLoss.dLossRatePercent()
                * static_cast<double>(vecEligibleIndexes.size())
                / 100.0
        ));
        m_setDroppedPacketIndexes.insert(
            vecEligibleIndexes.begin(),
            vecEligibleIndexes.begin()
                + static_cast<std::ptrdiff_t>(std::min(
                    nDropCount,
                    vecEligibleIndexes.size()
                ))
        );
    }

    DatagramFaultDecision decDecide(
        const protocol::ByteBuffer& vecDatagram,
        std::uint64_t
    ) override
    {
        const std::optional<std::uint32_t> optIndex = optPacketIndex(vecDatagram);
        if (optIndex.has_value()
            && m_setDroppedPacketIndexes.count(optIndex.value()) > 0)
        {
            return DatagramFaultDecision(
                DatagramFaultDisposition::Drop,
                0,
                "PACKET_LOSS_INJECTED"
            );
        }

        return DatagramFaultDecision(
            DatagramFaultDisposition::Send,
            0,
            "FAULT_PASS"
        );
    }

private:
    std::set<std::uint32_t> m_setDroppedPacketIndexes;
};

class LogicalDisconnectFaultPolicy final : public FaultPolicyBase
{
public:
    LogicalDisconnectFaultPolicy(
        const protocol::LogicalDisconnectFaultDetails& detDisconnect,
        const AuthenticationRoundParameters& prmRound
    )
        : FaultPolicyBase(prmRound, detDisconnect.u32ProtectedGroupSize()),
          m_u32StartPacketIndex(detDisconnect.u32StartPacketIndex()),
          m_u32DurationMilliseconds(detDisconnect.u32DurationMilliseconds())
    {
        if (m_u32StartPacketIndex > prmRound.u32TotalPacketCount())
        {
            throw std::invalid_argument(
                "Logical disconnect starts after the final data packet"
            );
        }
    }

    DatagramFaultDecision decDecide(
        const protocol::ByteBuffer& vecDatagram,
        std::uint64_t u64PlannedSendTimestampMilliseconds
    ) override
    {
        const std::optional<std::uint32_t> optIndex = optPacketIndex(vecDatagram);
        if (!optIndex.has_value())
        {
            return DatagramFaultDecision(
                DatagramFaultDisposition::Send,
                0,
                "FAULT_PASS"
            );
        }

        if (!m_optWindowStartMilliseconds.has_value()
            && optIndex.value() >= m_u32StartPacketIndex)
        {
            m_optWindowStartMilliseconds = u64PlannedSendTimestampMilliseconds;
        }

        const bool bInsideWindow = m_optWindowStartMilliseconds.has_value()
            && u64PlannedSendTimestampMilliseconds
                < m_optWindowStartMilliseconds.value()
                    + m_u32DurationMilliseconds;
        if (bInsideWindow && !bIsProtectedGroupEnd(optIndex.value()))
        {
            return DatagramFaultDecision(
                DatagramFaultDisposition::Drop,
                0,
                "LOGICAL_DISCONNECT_INJECTED"
            );
        }

        return DatagramFaultDecision(
            DatagramFaultDisposition::Send,
            0,
            bInsideWindow
                ? "PROTECTED_GROUP_END"
                : "FAULT_PASS"
        );
    }

private:
    std::uint32_t              m_u32StartPacketIndex;
    std::uint32_t              m_u32DurationMilliseconds;
    std::optional<std::uint64_t> m_optWindowStartMilliseconds;
};

class FixedDelayFaultPolicy final : public AuthenticationFaultPolicy
{
public:
    explicit FixedDelayFaultPolicy(
        const protocol::FixedDelayFaultDetails& detDelay
    )
        : m_u32DelayMilliseconds(detDelay.u32DelayMilliseconds())
    {
    }

    DatagramFaultDecision decDecide(
        const protocol::ByteBuffer&,
        std::uint64_t
    ) override
    {
        return DatagramFaultDecision(
            DatagramFaultDisposition::Send,
            m_u32DelayMilliseconds,
            m_u32DelayMilliseconds == 0
                ? "FAULT_PASS"
                : "FIXED_DELAY_INJECTED"
        );
    }

private:
    std::uint32_t m_u32DelayMilliseconds;
};
}

DatagramFaultDecision::DatagramFaultDecision(
    DatagramFaultDisposition dspDisposition,
    std::uint32_t u32DelayMilliseconds,
    std::string strReason
)
    : m_dspDisposition(dspDisposition),
      m_u32DelayMilliseconds(u32DelayMilliseconds),
      m_strReason(std::move(strReason))
{
    if (m_strReason.empty()
        || (m_dspDisposition == DatagramFaultDisposition::Drop
            && m_u32DelayMilliseconds != 0))
    {
        throw std::invalid_argument("Datagram fault decision is inconsistent");
    }
}

DatagramFaultDisposition DatagramFaultDecision::dspDisposition() const noexcept
{
    return m_dspDisposition;
}

std::uint32_t DatagramFaultDecision::u32DelayMilliseconds() const noexcept
{
    return m_u32DelayMilliseconds;
}

const std::string& DatagramFaultDecision::strReason() const noexcept
{
    return m_strReason;
}

std::unique_ptr<AuthenticationFaultPolicy> ptrCreateAuthenticationFaultPolicy(
    const protocol::AuthenticationFaultDetails& varFaultDetails,
    const AuthenticationRoundParameters& prmRound
)
{
    if (const auto* pLoss = std::get_if<protocol::PacketLossFaultDetails>(
            &varFaultDetails
        ))
    {
        return std::make_unique<PacketLossFaultPolicy>(*pLoss, prmRound);
    }
    if (const auto* pDisconnect = std::get_if<
            protocol::LogicalDisconnectFaultDetails
        >(&varFaultDetails))
    {
        return std::make_unique<LogicalDisconnectFaultPolicy>(
            *pDisconnect,
            prmRound
        );
    }

    return std::make_unique<FixedDelayFaultPolicy>(
        std::get<protocol::FixedDelayFaultDetails>(varFaultDetails)
    );
}
}
