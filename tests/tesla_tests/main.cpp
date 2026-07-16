#include "tesla/core/AuthenticationAuthority.h"
#include "tesla/core/AuthenticationGroupInput.h"
#include "tesla/core/AuthenticationInputEncoder.h"
#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/core/ImprovedAuthenticationDetails.h"
#include "tesla/core/ImprovedTeslaStrategy.h"
#include "tesla/core/ImprovedVerificationDetails.h"
#include "tesla/core/NativeAuthenticationDetails.h"
#include "tesla/core/NativePacketStatus.h"
#include "tesla/core/NativeTeslaStrategy.h"
#include "tesla/core/NativeVerificationDetails.h"
#include "tesla/core/ReceiverAuthenticationContextStore.h"
#include "tesla/core/SenderAuthenticationContext.h"
#include "tesla/core/TeslaAuthenticationMode.h"
#include "tesla/core/TeslaVerificationResult.h"
#include "tesla/crypto/CryptoAlgorithm.h"
#include "tesla/crypto/CryptoProvider.h"
#include "tesla/crypto/CryptoTypes.h"
#include "tesla/crypto/OpenSslCryptoProvider.h"
#include "tesla/crypto/SecureRandomProvider.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace
{
using tesla::core::AuthenticationGroupInput;
using tesla::core::AuthenticationAuthority;
using tesla::core::AuthenticationInputEncoder;
using tesla::core::AuthenticationPacketInput;
using tesla::core::AuthenticationRoundParameters;
using tesla::core::ImprovedAuthenticationDetails;
using tesla::core::ImprovedTeslaStrategy;
using tesla::core::ImprovedVerificationDetails;
using tesla::core::ImprovedVerificationPath;
using tesla::core::NativeAuthenticationDetails;
using tesla::core::NativePacketStatus;
using tesla::core::NativeTeslaStrategy;
using tesla::core::NativeVerificationDetails;
using tesla::core::ReceiverAuthenticationContext;
using tesla::core::ReceiverAuthenticationContextLookupError;
using tesla::core::ReceiverAuthenticationContextLookupResult;
using tesla::core::ReceiverAuthenticationContextStore;
using tesla::core::SenderAuthenticationContext;
using tesla::core::SenderAuthenticationMaterial;
using tesla::core::TeslaAuthenticationMode;
using tesla::core::TeslaAuthenticationDetails;
using tesla::core::TeslaVerificationResult;
using tesla::crypto::ByteBuffer;
using tesla::crypto::CryptoAlgorithm;
using tesla::crypto::CryptoProvider;
using tesla::crypto::Digest;
using tesla::crypto::OpenSslCryptoProvider;
using tesla::crypto::SecureRandomProvider;

// 注入确定性字节序列，稳定覆盖CA的chainId碰撞重试分支。
class QueuedSecureRandomProvider final : public SecureRandomProvider
{
public:
    explicit QueuedSecureRandomProvider(std::vector<ByteBuffer> vecOutputs)
        : m_vecOutputs(std::move(vecOutputs))
    {
    }

    ByteBuffer vecGenerateBytes(std::size_t nSize) const override
    {
        if (m_nNextOutput >= m_vecOutputs.size())
        {
            throw std::runtime_error("Deterministic random output queue is empty");
        }

        const ByteBuffer vecOutput = m_vecOutputs[m_nNextOutput++];
        if (vecOutput.size() != nSize)
        {
            throw std::runtime_error("Deterministic random output size mismatch");
        }

        return vecOutput;
    }

private:
    std::vector<ByteBuffer> m_vecOutputs;
    mutable std::size_t     m_nNextOutput = 0;
};

// 统计密码调用次数，用于证明快速路径没有退化为逐包HMAC验证。
class CountingCryptoProvider final : public CryptoProvider
{
public:
    explicit CountingCryptoProvider(CryptoAlgorithm algAlgorithm)
        : m_crpProvider(algAlgorithm)
    {
    }

    CryptoAlgorithm algAlgorithm() const noexcept override
    {
        return m_crpProvider.algAlgorithm();
    }

    Digest digHash(const ByteBuffer& vecData) const override
    {
        ++m_nHashCount;
        return m_crpProvider.digHash(vecData);
    }

    Digest digHmac(const ByteBuffer& vecKey, const ByteBuffer& vecData) const override
    {
        ++m_nHmacCount;
        return m_crpProvider.digHmac(vecKey, vecData);
    }

    std::size_t nHashCount() const noexcept
    {
        return m_nHashCount;
    }

    std::size_t nHmacCount() const noexcept
    {
        return m_nHmacCount;
    }

    void resetCounts() const noexcept
    {
        m_nHashCount = 0;
        m_nHmacCount = 0;
    }

private:
    OpenSslCryptoProvider  m_crpProvider;
    mutable std::size_t    m_nHashCount = 0;
    mutable std::size_t    m_nHmacCount = 0;
};

// 创建内容可预测但彼此不同的固定32字节测试消息。
AuthenticationPacketInput::Message arrCreateMessage(std::uint8_t u8BaseValue)
{
    AuthenticationPacketInput::Message arrMessage{};

    for (std::size_t nIndex = 0; nIndex < arrMessage.size(); ++nIndex)
    {
        arrMessage[nIndex] = static_cast<std::uint8_t>(u8BaseValue + nIndex);
    }

    return arrMessage;
}

// 构造可指定丢包或篡改位置的固定槽位认证组测试夹具。
AuthenticationGroupInput grpCreateGroup(
    std::size_t nPacketCount,
    const std::vector<std::size_t>& vecMissingPositions = {},
    const std::vector<std::size_t>& vecTamperedPositions = {}
)
{
    std::vector<AuthenticationGroupInput::PacketSlot> vecPacketSlots;
    vecPacketSlots.reserve(nPacketCount);

    for (std::size_t nPosition = 0; nPosition < nPacketCount; ++nPosition)
    {
        if (std::find(
                vecMissingPositions.begin(),
                vecMissingPositions.end(),
                nPosition
            ) != vecMissingPositions.end())
        {
            vecPacketSlots.push_back(std::nullopt);
            continue;
        }

        AuthenticationPacketInput::Message arrMessage = arrCreateMessage(
            static_cast<std::uint8_t>(0x10 + nPosition)
        );

        if (std::find(
                vecTamperedPositions.begin(),
                vecTamperedPositions.end(),
                nPosition
            ) != vecTamperedPositions.end())
        {
            arrMessage[0] ^= 0x01;
        }

        vecPacketSlots.emplace_back(AuthenticationPacketInput(
            "UAV-101",
            0x0102030405060708ULL,
            3,
            static_cast<std::uint32_t>(101 + nPosition),
            arrMessage
        ));
    }

    return AuthenticationGroupInput(
        "UAV-101",
        0x0102030405060708ULL,
        3,
        7,
        101,
        std::move(vecPacketSlots)
    );
}

// 使用当前算法确定性生成测试数据密钥。
Digest digCreateDataKey(const CryptoProvider& crpProvider)
{
    const std::string strSeed = "stage2-tesla-data-key";
    return crpProvider.digHash(ByteBuffer(strSeed.begin(), strSeed.end()));
}

// 统一记录断言失败，同时允许后续测试继续执行。
bool bExpect(bool bCondition, const std::string& strDescription)
{
    if (!bCondition)
    {
        std::cerr << "FAILED: " << strDescription << std::endl;
        return false;
    }

    return true;
}

// 固定检查单包和快速组输入的长度、字段顺序及大端编码。
bool bTestAlgorithmInputEncoding()
{
    const AuthenticationGroupInput grpInput = grpCreateGroup(2);
    const AuthenticationPacketInput& pktInput = grpInput.vecPacketSlots().front().value();
    const ByteBuffer vecMacInput = AuthenticationInputEncoder::vecEncodePacketMacInput(pktInput);

    bool bPassed = bExpect(vecMacInput.size() == 57, "MAC input length");
    bPassed = bExpect(vecMacInput[0] == 0 && vecMacInput[1] == 7, "Sender ID length encoding")
        && bPassed;
    bPassed = bExpect(
        std::equal(
            vecMacInput.begin() + 2,
            vecMacInput.begin() + 9,
            pktInput.strSenderId().begin()
        ),
        "Sender ID byte encoding"
    ) && bPassed;

    const std::vector<std::uint8_t> vecExpectedContextBytes = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x65
    };
    bPassed = bExpect(
        std::equal(
            vecMacInput.begin() + 9,
            vecMacInput.begin() + 25,
            vecExpectedContextBytes.begin()
        ),
        "Network-byte-order context encoding"
    ) && bPassed;

    const std::vector<Digest> vecSamdTau(2);
    const ByteBuffer vecFastGroupInput = AuthenticationInputEncoder::vecEncodeFastGroupInput(
        grpInput,
        vecSamdTau
    );
    bPassed = bExpect(vecFastGroupInput.size() == 169, "Fast-group input length") && bPassed;
    bPassed = bExpect(
        vecFastGroupInput[21] == 0
        && vecFastGroupInput[22] == 0
        && vecFastGroupInput[23] == 0
        && vecFastGroupInput[24] == 7,
        "Fast-group index encoding"
    ) && bPassed;
    bPassed = bExpect(
        vecFastGroupInput[25] == 0
        && vecFastGroupInput[26] == 0
        && vecFastGroupInput[27] == 0
        && vecFastGroupInput[28] == 2,
        "Fast-group packet-count encoding"
    ) && bPassed;
    bPassed = bExpect(
        vecFastGroupInput[101] == 0
        && vecFastGroupInput[102] == 0
        && vecFastGroupInput[103] == 0
        && vecFastGroupInput[104] == 2,
        "Fast-group tau-count encoding"
    ) && bPassed;

    return bPassed;
}

// 验证原生模式正常组通过，并能在variant详情中标记精确篡改位置。
bool bTestNativeStrategy(CryptoAlgorithm algAlgorithm)
{
    const OpenSslCryptoProvider crpProvider(algAlgorithm);
    const NativeTeslaStrategy   stgStrategy(crpProvider);
    const AuthenticationGroupInput grpOriginal = grpCreateGroup(4);
    const Digest digDataKey = digCreateDataKey(crpProvider);
    const TeslaAuthenticationDetails varDetails = stgStrategy.authCreateAuthenticationDetails(
        grpOriginal,
        digDataKey
    );
    const TeslaVerificationResult vfyOriginal = stgStrategy.vfyVerify(
        grpOriginal,
        varDetails,
        digDataKey
    );

    bool bPassed = bExpect(vfyOriginal.bPassed(), "Native group verification");
    bPassed = bExpect(
        std::holds_alternative<NativeVerificationDetails>(vfyOriginal.varDetails()),
        "Native verification variant"
    ) && bPassed;

    const AuthenticationGroupInput grpTampered = grpCreateGroup(4, {}, {1});
    const TeslaVerificationResult vfyTampered = stgStrategy.vfyVerify(
        grpTampered,
        varDetails,
        digDataKey
    );
    const NativeVerificationDetails& detTampered =
        std::get<NativeVerificationDetails>(vfyTampered.varDetails());

    bPassed = bExpect(!vfyTampered.bPassed(), "Native tamper rejection") && bPassed;
    bPassed = bExpect(
        detTampered.vecPacketStatuses()[1] == NativePacketStatus::MacFailed,
        "Native tampered packet status"
    ) && bPassed;

    return bPassed;
}

// 验证三套算法均可走快速组路径，并通过调用计数确认未计算逐包HMAC。
bool bTestImprovedFastPath(CryptoAlgorithm algAlgorithm)
{
    CountingCryptoProvider crpProvider(algAlgorithm);
    const ImprovedTeslaStrategy stgStrategy(crpProvider, 4, 1);
    const AuthenticationGroupInput grpOriginal = grpCreateGroup(4);
    const Digest digDataKey = digCreateDataKey(crpProvider);
    const TeslaAuthenticationDetails varDetails = stgStrategy.authCreateAuthenticationDetails(
        grpOriginal,
        digDataKey
    );

    crpProvider.resetCounts();
    const TeslaVerificationResult vfyResult = stgStrategy.vfyVerify(
        grpOriginal,
        varDetails,
        digDataKey
    );
    const ImprovedVerificationDetails& detResult =
        std::get<ImprovedVerificationDetails>(vfyResult.varDetails());

    return bExpect(vfyResult.bPassed(), "Improved fast-group verification")
        && bExpect(
            detResult.pathVerification() == ImprovedVerificationPath::FastGroupPass,
            "Improved fast-group path"
        )
        && bExpect(detResult.bFastGroupTagMatched(), "Fast-group tag match")
        && bExpect(crpProvider.nHashCount() == 1, "Fast path hash count")
        && bExpect(crpProvider.nHmacCount() == 2, "Fast path avoids per-packet HMAC");
}

// 覆盖篡改、单点丢包、全部丢包、超过门限和标签不完整等回退场景。
bool bTestImprovedFallbacks()
{
    const OpenSslCryptoProvider crpProvider(CryptoAlgorithm::Sha256);
    const ImprovedTeslaStrategy stgStrategy(crpProvider, 4, 1);
    const AuthenticationGroupInput grpOriginal = grpCreateGroup(4);
    const Digest digDataKey = digCreateDataKey(crpProvider);
    const TeslaAuthenticationDetails varDetails = stgStrategy.authCreateAuthenticationDetails(
        grpOriginal,
        digDataKey
    );
    bool bPassed = true;

    // 快速标签失败后，KS+RS应定位被篡改的固定位置1。
    const AuthenticationGroupInput grpTampered = grpCreateGroup(4, {}, {1});
    const TeslaVerificationResult vfyTampered = stgStrategy.vfyVerify(
        grpTampered,
        varDetails,
        digDataKey
    );
    const ImprovedVerificationDetails& detTampered =
        std::get<ImprovedVerificationDetails>(vfyTampered.varDetails());
    bPassed = bExpect(
        detTampered.pathVerification() == ImprovedVerificationPath::KsRsFallback,
        "Tampered group fallback path"
    ) && bPassed;
    bPassed = bExpect(
        detTampered.vecRejectedPositions().size() == 1
        && detTampered.vecRejectedPositions().front() == 1,
        "Exact tampered packet location"
    ) && bPassed;
    bPassed = bExpect(
        !detTampered.bDetectionThresholdExceeded(),
        "Within-threshold tamper location"
    ) && bPassed;

    // 丢包位置2不得因压缩槽位而改变矩阵列。
    const AuthenticationGroupInput grpMissing = grpCreateGroup(4, {2});
    const TeslaVerificationResult vfyMissing = stgStrategy.vfyVerify(
        grpMissing,
        varDetails,
        digDataKey
    );
    const ImprovedVerificationDetails& detMissing =
        std::get<ImprovedVerificationDetails>(vfyMissing.varDetails());
    bPassed = bExpect(
        detMissing.pathVerification() == ImprovedVerificationPath::KsRsFallback,
        "Missing packet fallback path"
    ) && bPassed;
    bPassed = bExpect(
        detMissing.vecRejectedPositions().size() == 1
        && detMissing.vecRejectedPositions().front() == 2,
        "Missing slot retains exact matrix position"
    ) && bPassed;

    // 即使整组都未收到，也必须保留并拒绝全部四个固定槽位。
    const AuthenticationGroupInput grpAllMissing = grpCreateGroup(4, {0, 1, 2, 3});
    const TeslaVerificationResult vfyAllMissing = stgStrategy.vfyVerify(
        grpAllMissing,
        varDetails,
        digDataKey
    );
    const ImprovedVerificationDetails& detAllMissing =
        std::get<ImprovedVerificationDetails>(vfyAllMissing.varDetails());
    bPassed = bExpect(
        detAllMissing.vecRejectedPositions().size() == 4,
        "All-missing group retains every fixed slot"
    ) && bPassed;

    // 两个异常位置超过配置门限1，结果需显式报告门限超限。
    const AuthenticationGroupInput grpOverThreshold = grpCreateGroup(4, {}, {1, 2});
    const TeslaVerificationResult vfyOverThreshold = stgStrategy.vfyVerify(
        grpOverThreshold,
        varDetails,
        digDataKey
    );
    const ImprovedVerificationDetails& detOverThreshold =
        std::get<ImprovedVerificationDetails>(vfyOverThreshold.varDetails());
    bPassed = bExpect(
        detOverThreshold.bDetectionThresholdExceeded(),
        "Detection-threshold exceeded result"
    ) && bPassed;

    // 缺少完整tau和快速组标签时，不应尝试不可靠的回退验证。
    const ImprovedAuthenticationDetails detIncomplete({}, std::nullopt);
    const TeslaVerificationResult vfyIncomplete = stgStrategy.vfyVerify(
        grpOriginal,
        TeslaAuthenticationDetails(detIncomplete),
        digDataKey
    );
    const ImprovedVerificationDetails& detIncompleteResult =
        std::get<ImprovedVerificationDetails>(vfyIncomplete.varDetails());
    bPassed = bExpect(
        detIncompleteResult.pathVerification() == ImprovedVerificationPath::IncompleteGroupTags,
        "Incomplete group tags result"
    ) && bPassed;

    return bPassed;
}

// 验证小于配置组大小的尾组仍能生成并通过快速组标签。
bool bTestImprovedTailGroup()
{
    const OpenSslCryptoProvider crpProvider(CryptoAlgorithm::Sha256);
    const ImprovedTeslaStrategy stgStrategy(crpProvider, 4, 1);
    const AuthenticationGroupInput grpTail = grpCreateGroup(3);
    const Digest digDataKey = digCreateDataKey(crpProvider);
    const TeslaAuthenticationDetails varDetails = stgStrategy.authCreateAuthenticationDetails(
        grpTail,
        digDataKey
    );
    const TeslaVerificationResult vfyResult = stgStrategy.vfyVerify(
        grpTail,
        varDetails,
        digDataKey
    );

    return bExpect(vfyResult.bPassed(), "Partial tail group verification")
        && bExpect(
            std::get<ImprovedVerificationDetails>(vfyResult.varDetails()).pathVerification()
                == ImprovedVerificationPath::FastGroupPass,
            "Partial tail group fast path"
        );
}

// 验证CA独立签发、Sender本地K0自检，以及Receiver先按来源IP映射的事务上下文。
bool bTestAuthenticationProvisioning()
{
    const ByteBuffer vecChainIdOne{0, 0, 0, 0, 0, 0, 0, 1};
    const ByteBuffer vecChainIdTwo{0, 0, 0, 0, 0, 0, 0, 2};
    const ByteBuffer vecSeedOne(32, 0x11);
    const ByteBuffer vecSeedTwo(32, 0x22);
    const QueuedSecureRandomProvider rngProvider({
        vecChainIdOne,
        vecSeedOne,
        vecChainIdOne,
        vecChainIdTwo,
        vecSeedTwo
    });
    AuthenticationAuthority autAuthority(rngProvider);
    const AuthenticationRoundParameters prmRound(
        CryptoAlgorithm::Sha256,
        TeslaAuthenticationMode::Native,
        10,
        4,
        3,
        100,
        1'700'000'000'000ULL
    );

    SenderAuthenticationMaterial matOne = autAuthority.matIssueSenderMaterial(
        "UAV-201",
        prmRound
    );
    SenderAuthenticationMaterial matTwo = autAuthority.matIssueSenderMaterial(
        "UAV-202",
        prmRound
    );

    bool bPassed = bExpect(
        prmRound.nDataIntervalCount() == 3 && prmRound.u32ChainLength() == 4,
        "Key-chain length uses ceil(packetCount/packetsPerInterval)+1"
    );
    bPassed = bExpect(
        matOne.u64ChainId() != matTwo.u64ChainId()
            && matOne.vecChainSeed() != matTwo.vecChainSeed()
            && matOne.digCommitmentKey() != matTwo.digCommitmentKey(),
        "Different senders receive distinct chain ID, seed, and K0"
    ) && bPassed;

    const OpenSslCryptoProvider crpProvider(CryptoAlgorithm::Sha256);
    const SenderAuthenticationContext ctxSender =
        SenderAuthenticationContext::ctxCreateVerified(matOne, crpProvider);
    bPassed = bExpect(
        ctxSender.keyChain().nDataIntervalCount() == 3,
        "Sender rebuilds the complete configured key chain"
    ) && bPassed;

    Digest digTamperedCommitment = matOne.digCommitmentKey();
    digTamperedCommitment[0] ^= 0x01;
    bool bRejectedTamperedCommitment = false;
    try
    {
        static_cast<void>(SenderAuthenticationContext::ctxCreateVerified(
            SenderAuthenticationMaterial(
                matOne.strSenderId(),
                matOne.u64ChainId(),
                matOne.vecChainSeed(),
                digTamperedCommitment,
                matOne.prmRoundParameters()
            ),
            crpProvider
        ));
    }
    catch (const std::invalid_argument&)
    {
        bRejectedTamperedCommitment = true;
    }
    bPassed = bExpect(
        bRejectedTamperedCommitment,
        "Sender rejects a supplied K0 that does not match the rebuilt chain"
    ) && bPassed;

    ReceiverAuthenticationContextStore stoContexts;
    const ReceiverAuthenticationContext ctxOne =
        autAuthority.ctxCreateReceiverContext(matOne, "127.0.0.21");
    const ReceiverAuthenticationContext ctxTwo =
        autAuthority.ctxCreateReceiverContext(matTwo, "127.0.0.22");
    stoContexts.replaceAll({ctxOne, ctxTwo});

    const ReceiverAuthenticationContextLookupResult resKnown = stoContexts.resFind(
        "127.0.0.21",
        matOne.u64ChainId()
    );
    const ReceiverAuthenticationContextLookupResult resUnknownSource =
        stoContexts.resFind("127.0.0.99", matOne.u64ChainId());
    const ReceiverAuthenticationContextLookupResult resWrongChain =
        stoContexts.resFind("127.0.0.21", matTwo.u64ChainId());

    bPassed = bExpect(
        std::holds_alternative<ReceiverAuthenticationContext>(resKnown)
            && std::get<ReceiverAuthenticationContext>(resKnown).strSenderId()
                == matOne.strSenderId(),
        "Receiver resolves sender context from trusted source IP and chain ID"
    ) && bPassed;
    bPassed = bExpect(
        std::get<ReceiverAuthenticationContextLookupError>(resUnknownSource)
            == ReceiverAuthenticationContextLookupError::UnknownSourceIp,
        "Receiver rejects an unknown source IP before chain lookup"
    ) && bPassed;
    bPassed = bExpect(
        std::get<ReceiverAuthenticationContextLookupError>(resWrongChain)
            == ReceiverAuthenticationContextLookupError::UnknownChainId,
        "Receiver does not accept another sender's chain ID for a trusted IP"
    ) && bPassed;

    bool bRejectedConflictingMapping = false;
    try
    {
        stoContexts.replaceAll({
            ctxOne,
            autAuthority.ctxCreateReceiverContext(matTwo, "127.0.0.21")
        });
    }
    catch (const std::invalid_argument&)
    {
        bRejectedConflictingMapping = true;
    }

    bPassed = bExpect(
        bRejectedConflictingMapping
            && stoContexts.nSize() == 2
            && std::holds_alternative<ReceiverAuthenticationContext>(
                stoContexts.resFind("127.0.0.21", matOne.u64ChainId())
            ),
        "Rejected receiver update preserves the previous complete context set"
    ) && bPassed;

    return bPassed;
}
}

int main()
{
    bool bPassed = true;
    bPassed = bTestAlgorithmInputEncoding() && bPassed;

    for (CryptoAlgorithm algAlgorithm : {
             CryptoAlgorithm::Sha256,
             CryptoAlgorithm::Sm3,
             CryptoAlgorithm::Sha3_256
         })
    {
        bPassed = bTestNativeStrategy(algAlgorithm) && bPassed;
        bPassed = bTestImprovedFastPath(algAlgorithm) && bPassed;
    }

    bPassed = bTestImprovedFallbacks() && bPassed;
    bPassed = bTestImprovedTailGroup() && bPassed;
    bPassed = bTestAuthenticationProvisioning() && bPassed;

    if (!bPassed)
    {
        return 1;
    }

    std::cout << "All TESLA core tests passed." << std::endl;
    return 0;
}
