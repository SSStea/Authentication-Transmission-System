#include "tesla/metrics/PerformanceCounterSampler.h"

#include <chrono>
#include <cstdint>
#include <memory>

#if defined(__linux__)
#include <cerrno>
#include <cstring>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace tesla::metrics
{
namespace
{
using SteadyClock = std::chrono::steady_clock;

class SteadyClockPerformanceSampler : public VerificationPerformanceSampler
{
public:
    void begin() override
    {
        m_tpStart = SteadyClock::now();
    }

    PerformanceMeasurement mstEnd() noexcept override
    {
        const std::uint64_t u64DurationNanoseconds =
            static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    SteadyClock::now() - m_tpStart
                ).count()
            );
        return PerformanceMeasurement(
            u64DurationNanoseconds,
            HardwarePerformanceCounters(
                HardwareCounterStatus::NotSupported,
                0,
                0,
                0
            )
        );
    }

private:
    SteadyClock::time_point m_tpStart{SteadyClock::now()};
};

#if defined(__linux__)
class LinuxPerfPerformanceSampler final : public VerificationPerformanceSampler
{
public:
    ~LinuxPerfPerformanceSampler() override
    {
        closeCounters();
    }

    void begin() override
    {
        m_tpStart = SteadyClock::now();
        if (!m_bInitializationAttempted)
        {
            initializeCounters();
        }

        if (m_statusCounters == HardwareCounterStatus::Supported)
        {
            if (ioctl(m_nCyclesFd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0
                || ioctl(m_nCyclesFd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0)
            {
                m_statusCounters = HardwareCounterStatus::ReadFailed;
                closeCounters();
            }
        }
    }

    PerformanceMeasurement mstEnd() noexcept override
    {
        const std::uint64_t u64DurationNanoseconds =
            static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    SteadyClock::now() - m_tpStart
                ).count()
            );
        std::uint64_t u64Cycles = 0;
        std::uint64_t u64References = 0;
        std::uint64_t u64Misses = 0;

        if (m_statusCounters == HardwareCounterStatus::Supported)
        {
            if (ioctl(m_nCyclesFd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) != 0
                || !bReadCounter(m_nCyclesFd, u64Cycles)
                || !bReadCounter(m_nReferencesFd, u64References)
                || !bReadCounter(m_nMissesFd, u64Misses))
            {
                m_statusCounters = HardwareCounterStatus::ReadFailed;
                u64Cycles = 0;
                u64References = 0;
                u64Misses = 0;
                closeCounters();
            }
        }

        return PerformanceMeasurement(
            u64DurationNanoseconds,
            HardwarePerformanceCounters(
                m_statusCounters,
                u64Cycles,
                u64References,
                u64Misses
            )
        );
    }

private:
    static int nOpenCounter(std::uint32_t u32Config, int nGroupFd)
    {
        perf_event_attr atrEvent{};
        atrEvent.type = PERF_TYPE_HARDWARE;
        atrEvent.size = sizeof(atrEvent);
        atrEvent.config = u32Config;
        atrEvent.disabled = 1;
        atrEvent.exclude_kernel = 1;
        atrEvent.exclude_hv = 1;
        return static_cast<int>(syscall(
            __NR_perf_event_open,
            &atrEvent,
            0,
            -1,
            nGroupFd,
            0
        ));
    }

    static bool bReadCounter(int nFileDescriptor, std::uint64_t& u64Value) noexcept
    {
        return read(nFileDescriptor, &u64Value, sizeof(u64Value))
            == static_cast<ssize_t>(sizeof(u64Value));
    }

    void initializeCounters()
    {
        m_bInitializationAttempted = true;
        m_nCyclesFd = nOpenCounter(PERF_COUNT_HW_CPU_CYCLES, -1);
        if (m_nCyclesFd < 0)
        {
            m_statusCounters = (errno == EACCES || errno == EPERM)
                ? HardwareCounterStatus::PermissionDenied
                : HardwareCounterStatus::NotSupported;
            return;
        }

        m_nReferencesFd = nOpenCounter(
            PERF_COUNT_HW_CACHE_REFERENCES,
            m_nCyclesFd
        );
        m_nMissesFd = nOpenCounter(PERF_COUNT_HW_CACHE_MISSES, m_nCyclesFd);
        if (m_nReferencesFd < 0 || m_nMissesFd < 0)
        {
            m_statusCounters = (errno == EACCES || errno == EPERM)
                ? HardwareCounterStatus::PermissionDenied
                : HardwareCounterStatus::NotSupported;
            closeCounters();
            return;
        }

        m_statusCounters = HardwareCounterStatus::Supported;
    }

    void closeCounters() noexcept
    {
        if (m_nMissesFd >= 0)
        {
            close(m_nMissesFd);
            m_nMissesFd = -1;
        }
        if (m_nReferencesFd >= 0)
        {
            close(m_nReferencesFd);
            m_nReferencesFd = -1;
        }
        if (m_nCyclesFd >= 0)
        {
            close(m_nCyclesFd);
            m_nCyclesFd = -1;
        }
    }

    SteadyClock::time_point m_tpStart{SteadyClock::now()};
    HardwareCounterStatus   m_statusCounters{HardwareCounterStatus::NotSupported};
    bool                    m_bInitializationAttempted{false};
    int                     m_nCyclesFd{-1};
    int                     m_nReferencesFd{-1};
    int                     m_nMissesFd{-1};
};
#endif
}

std::unique_ptr<VerificationPerformanceSampler>
ptrCreateVerificationPerformanceSampler()
{
#if defined(__linux__)
    return std::make_unique<LinuxPerfPerformanceSampler>();
#else
    return std::make_unique<SteadyClockPerformanceSampler>();
#endif
}
}
