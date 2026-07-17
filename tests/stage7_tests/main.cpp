#include "tesla/core/AuthenticationAuthority.h"
#include "tesla/core/AuthenticationNodeRuntime.h"
#include "tesla/core/AuthenticationPacketInput.h"
#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/core/FileUploadSession.h"
#include "tesla/crypto/OpenSslCryptoProvider.h"
#include "tesla/crypto/OpenSslSecureRandomProvider.h"
#include "tesla/protocol/NodeControlJsonCodec.h"
#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/protocol/TcpFrame.h"
#include "tesla/workload/FileWorkload.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace
{
using namespace tesla;

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

protocol::BinaryBlock arrBlock(const crypto::ByteBuffer& vecBytes)
{
    if (vecBytes.size() != protocol::BINARY_BLOCK_SIZE)
    {
        throw std::invalid_argument("Test authentication block is not 32 bytes");
    }

    protocol::BinaryBlock arrResult{};
    std::copy(vecBytes.begin(), vecBytes.end(), arrResult.begin());
    return arrResult;
}

protocol::BinaryBlock arrBlock(const crypto::Digest& digValue)
{
    protocol::BinaryBlock arrResult{};
    std::copy(digValue.begin(), digValue.end(), arrResult.begin());
    return arrResult;
}

protocol::AuthenticationCryptoAlgorithm algControl(
    crypto::CryptoAlgorithm algCrypto
)
{
    switch (algCrypto)
    {
    case crypto::CryptoAlgorithm::Sha256:
        return protocol::AuthenticationCryptoAlgorithm::Sha256;
    case crypto::CryptoAlgorithm::Sm3:
        return protocol::AuthenticationCryptoAlgorithm::Sm3;
    case crypto::CryptoAlgorithm::Sha3_256:
        return protocol::AuthenticationCryptoAlgorithm::Sha3_256;
    }

    throw std::invalid_argument("Unsupported test crypto algorithm");
}

protocol::AuthenticationRoundControlParameters prmControl(
    const core::AuthenticationRoundParameters& prmRound
)
{
    std::optional<protocol::ImprovedTeslaControlParameters>
        optImprovedParameters;
    if (prmRound.optImprovedParameters().has_value())
    {
        optImprovedParameters.emplace(
            prmRound.optImprovedParameters()->u32GroupSize(),
            prmRound.optImprovedParameters()->u32DetectionThreshold()
        );
    }

    return protocol::AuthenticationRoundControlParameters(
        algControl(prmRound.algCryptoAlgorithm()),
        prmRound.modeAuthentication() == core::TeslaAuthenticationMode::Native
            ? protocol::UdpAuthenticationMode::Native
            : protocol::UdpAuthenticationMode::Improved,
        prmRound.u32TotalPacketCount(),
        prmRound.u32PacketsPerInterval(),
        prmRound.u32DisclosureDelay(),
        prmRound.u32IntervalMilliseconds(),
        prmRound.u64StartTimestampMilliseconds(),
        prmRound.u32ChainLength(),
        std::move(optImprovedParameters),
        protocol::AuthenticationPayloadMode::File
    );
}

bool bConfigAccepted(
    const protocol::NodeControlMessage& msgMessage,
    protocol::AuthenticationConfigTarget targetConfig
)
{
    if (msgMessage.typeMessage()
        != protocol::NodeControlMessageType::AuthenticationConfigAcknowledgement)
    {
        return false;
    }

    const auto& detAcknowledgement = std::get<
        protocol::AuthenticationConfigAcknowledgementControlDetails
    >(msgMessage.varDetails());
    return detAcknowledgement.bAccepted()
        && detAcknowledgement.targetConfig() == targetConfig;
}

bool bRoundAccepted(const protocol::NodeControlMessage& msgMessage)
{
    if (msgMessage.typeMessage()
        != protocol::NodeControlMessageType::RoundCommandAcknowledgement)
    {
        return false;
    }

    return std::get<
        protocol::AuthenticationRoundAcknowledgementControlDetails
    >(msgMessage.varDetails()).bAccepted();
}

class ResultCollector final
{
public:
    void add(const protocol::NodeControlMessage& msgMessage)
    {
        if (msgMessage.typeMessage()
            != protocol::NodeControlMessageType::RoundResult)
        {
            return;
        }

        std::lock_guard<std::mutex> lckResults(m_mtxResults);
        m_vecResults.push_back(std::get<
            protocol::AuthenticationRoundResultControlDetails
        >(msgMessage.varDetails()));
        m_cndResults.notify_all();
    }

    bool bWait(std::chrono::milliseconds durTimeout)
    {
        std::unique_lock<std::mutex> lckResults(m_mtxResults);
        return m_cndResults.wait_for(
            lckResults,
            durTimeout,
            [this]()
            {
                return !m_vecResults.empty();
            }
        );
    }

    protocol::AuthenticationRoundResultControlDetails detFirst() const
    {
        std::lock_guard<std::mutex> lckResults(m_mtxResults);
        if (m_vecResults.empty())
        {
            throw std::logic_error("Stage 7 result collector is empty");
        }
        return m_vecResults.front();
    }

private:
    mutable std::mutex m_mtxResults;
    std::condition_variable m_cndResults;
    std::vector<protocol::AuthenticationRoundResultControlDetails>
        m_vecResults;
};

std::vector<std::uint8_t> vecPattern(std::size_t nByteCount)
{
    std::vector<std::uint8_t> vecBytes(nByteCount);
    for (std::size_t nIndex = 0; nIndex < vecBytes.size(); ++nIndex)
    {
        vecBytes[nIndex] = static_cast<std::uint8_t>(nIndex % 251U);
    }
    return vecBytes;
}

bool bCheckWorkloadBoundaries()
{
    static_assert(!std::is_same_v<
        workload::FileWorkload::Message,
        protocol::FileBinaryChunk
    >);
    static_assert(!std::is_same_v<
        workload::FileWorkload::Message,
        core::AuthenticationPacketInput
    >);

    const std::vector<std::size_t> vecSizes{
        1U,
        31U,
        32U,
        33U,
        320000U,
        workload::FileWorkload::MAXIMUM_FILE_SIZE
    };
    for (std::size_t nByteCount : vecSizes)
    {
        const std::vector<std::uint8_t> vecOriginal = vecPattern(nByteCount);
        const workload::FileWorkload wrkFile(vecOriginal);
        const std::uint32_t u32ExpectedPacketCount =
            static_cast<std::uint32_t>((nByteCount + 31U) / 32U);
        if (wrkFile.u32PacketCount() != u32ExpectedPacketCount)
        {
            return false;
        }

        std::vector<workload::FileWorkload::Message> vecMessages;
        vecMessages.reserve(u32ExpectedPacketCount);
        for (std::uint32_t u32PacketIndex = 1;
             u32PacketIndex <= u32ExpectedPacketCount;
             ++u32PacketIndex)
        {
            vecMessages.push_back(wrkFile.arrMessage(u32PacketIndex));
        }

        if (nByteCount % workload::FileWorkload::MESSAGE_SIZE != 0)
        {
            const auto& arrLastMessage = vecMessages.back();
            const std::size_t nUsedByteCount = nByteCount
                % workload::FileWorkload::MESSAGE_SIZE;
            if (!std::all_of(
                    arrLastMessage.begin()
                        + static_cast<std::ptrdiff_t>(nUsedByteCount),
                    arrLastMessage.end(),
                    [](std::uint8_t u8Value)
                    {
                        return u8Value == 0;
                    }
                ))
            {
                return false;
            }
        }

        if (workload::FileWorkload::vecRecover(vecMessages, nByteCount)
            != vecOriginal)
        {
            return false;
        }
    }

    try
    {
        static_cast<void>(workload::FileWorkload({}));
        return false;
    }
    catch (const std::invalid_argument&)
    {
    }

    try
    {
        static_cast<void>(workload::FileWorkload(
            std::vector<std::uint8_t>(
                workload::FileWorkload::MAXIMUM_FILE_SIZE + 1U,
                0
            )
        ));
        return false;
    }
    catch (const std::invalid_argument&)
    {
    }

    return true;
}

bool bCheckUploadSession()
{
    const std::uint64_t u64ChainId = 0x1020304050607080ULL;
    const std::vector<std::uint8_t> vecOriginal = vecPattern(70000U);
    core::FileUploadSession uplFile;
    uplFile.begin("upload-success", u64ChainId, vecOriginal.size());
    uplFile.append(protocol::FileBinaryChunk(
        u64ChainId,
        1,
        protocol::ByteBuffer(vecOriginal.begin(), vecOriginal.begin() + 65536)
    ));
    uplFile.append(protocol::FileBinaryChunk(
        u64ChainId,
        2,
        protocol::ByteBuffer(vecOriginal.begin() + 65536, vecOriginal.end())
    ));
    const workload::FileWorkload wrkCompleted = uplFile.wrkComplete(
        "upload-success",
        u64ChainId,
        2,
        vecOriginal.size()
    );
    if (wrkCompleted.vecFileBytes() != vecOriginal || uplFile.bIsActive())
    {
        return false;
    }

    bool bRejectedOutOfOrder = false;
    uplFile.begin("upload-order", u64ChainId, 32);
    try
    {
        uplFile.append(protocol::FileBinaryChunk(
            u64ChainId,
            2,
            protocol::ByteBuffer(32, 0xA5)
        ));
    }
    catch (const std::invalid_argument&)
    {
        bRejectedOutOfOrder = true;
    }
    uplFile.reset();

    bool bRejectedMismatchedRequest = false;
    uplFile.begin("upload-request", u64ChainId, 32);
    uplFile.append(protocol::FileBinaryChunk(
        u64ChainId,
        1,
        protocol::ByteBuffer(32, 0xC3)
    ));
    try
    {
        static_cast<void>(uplFile.wrkComplete(
            "another-request",
            u64ChainId,
            1,
            32
        ));
    }
    catch (const std::invalid_argument&)
    {
        bRejectedMismatchedRequest = true;
    }
    uplFile.reset();

    bool bRejectedShortChunk = false;
    uplFile.begin("upload-short", u64ChainId, 65537);
    try
    {
        uplFile.append(protocol::FileBinaryChunk(
            u64ChainId,
            1,
            protocol::ByteBuffer(1, 0x11)
        ));
    }
    catch (const std::invalid_argument&)
    {
        bRejectedShortChunk = true;
    }
    uplFile.reset();

    bool bRejectedOversizeChunk = false;
    uplFile.begin("upload-oversize", u64ChainId, 65537);
    try
    {
        uplFile.append(protocol::FileBinaryChunk(
            u64ChainId,
            1,
            protocol::ByteBuffer(65537, 0x5A)
        ));
    }
    catch (const std::invalid_argument&)
    {
        bRejectedOversizeChunk = true;
    }
    uplFile.reset();
    return bRejectedOutOfOrder
        && bRejectedMismatchedRequest
        && bRejectedShortChunk
        && bRejectedOversizeChunk;
}

bool bCheckFileProtocolVariants()
{
    const protocol::AuthenticationRoundControlParameters prmRound(
        protocol::AuthenticationCryptoAlgorithm::Sha256,
        protocol::UdpAuthenticationMode::Native,
        2,
        2,
        1,
        100,
        0,
        2,
        std::nullopt,
        protocol::AuthenticationPayloadMode::File
    );
    const protocol::NodeControlMessage msgReceiver(
        protocol::ReceiverAuthenticationContextsControlDetails(
            "receiver-file",
            {
                protocol::ReceiverAuthenticationContextControlDetails(
                    "SENDER-FILE",
                    "10.0.0.1",
                    99,
                    protocol::BinaryBlock{},
                    prmRound,
                    protocol::FileReceiverPayloadControlDetails(33)
                )
            }
        )
    );
    const std::string strReceiverJson =
        protocol::NodeControlJsonCodec::strEncode(msgReceiver);
    if (strReceiverJson.find("originalSha256") != std::string::npos)
    {
        return false;
    }

    const auto resReceiver = protocol::NodeControlJsonCodec::resDecode(
        strReceiverJson
    );
    if (!std::holds_alternative<protocol::NodeControlMessage>(resReceiver))
    {
        return false;
    }

    std::string strSecretJson = strReceiverJson;
    const std::string strMarker = "\"payloadDetails\":{";
    const std::size_t nPayloadPosition = strSecretJson.find(strMarker);
    if (nPayloadPosition == std::string::npos)
    {
        return false;
    }
    strSecretJson.insert(
        nPayloadPosition + strMarker.size(),
        "\"originalSha256\":\"forbidden\","
    );
    if (!std::holds_alternative<protocol::ProtocolDecodeError>(
            protocol::NodeControlJsonCodec::resDecode(strSecretJson)
        ))
    {
        return false;
    }

    const protocol::NodeControlMessage msgUploadBegin(
        protocol::FileUploadBeginControlDetails(
            "upload-file",
            99,
            33
        )
    );
    const protocol::NodeControlMessage msgUploadEnd(
        protocol::FileUploadEndControlDetails(
            "upload-file",
            99,
            1,
            33
        )
    );
    const auto resUploadBegin = protocol::NodeControlJsonCodec::resDecode(
        protocol::NodeControlJsonCodec::strEncode(msgUploadBegin)
    );
    const auto resUploadEnd = protocol::NodeControlJsonCodec::resDecode(
        protocol::NodeControlJsonCodec::strEncode(msgUploadEnd)
    );
    if (!std::holds_alternative<protocol::NodeControlMessage>(resUploadBegin)
        || !std::holds_alternative<protocol::NodeControlMessage>(resUploadEnd)
        || std::get<protocol::NodeControlMessage>(resUploadBegin).typeMessage()
            != protocol::NodeControlMessageType::FileUploadBegin
        || std::get<protocol::NodeControlMessage>(resUploadEnd).typeMessage()
            != protocol::NodeControlMessageType::FileUploadEnd)
    {
        return false;
    }

    protocol::BinaryBlock arrRecoveredHash{};
    arrRecoveredHash.fill(0x3C);
    const protocol::NodeControlMessage msgResult(
        protocol::AuthenticationRoundResultControlDetails(
            "file-round",
            "SENDER-FILE",
            99,
            protocol::AuthenticationRoundResultRole::Receiver,
            protocol::AuthenticationRoundResultStatus::Completed,
            2,
            2,
            2,
            0,
            0,
            protocol::FileReceiverAuthenticationRoundResultDetails(
                33,
                33,
                arrRecoveredHash
            ),
            "completed"
        )
    );
    const auto resResult = protocol::NodeControlJsonCodec::resDecode(
        protocol::NodeControlJsonCodec::strEncode(msgResult)
    );
    return std::holds_alternative<protocol::NodeControlMessage>(resResult)
        && std::holds_alternative<
            protocol::FileReceiverAuthenticationRoundResultDetails
        >(std::get<protocol::AuthenticationRoundResultControlDetails>(
            std::get<protocol::NodeControlMessage>(resResult).varDetails()
        ).varResultDetails());
}

bool bRunFileRound(
    core::TeslaAuthenticationMode modeAuthentication,
    crypto::CryptoAlgorithm algAuthentication,
    bool bPersistenceAccepted
)
{
    const std::vector<std::uint8_t> vecOriginal = vecPattern(65);
    std::optional<core::ImprovedTeslaParameters> optImprovedParameters;
    if (modeAuthentication == core::TeslaAuthenticationMode::Improved)
    {
        optImprovedParameters.emplace(2, 1);
    }

    const core::AuthenticationRoundParameters prmRound(
        algAuthentication,
        modeAuthentication,
        3,
        4,
        1,
        120,
        0,
        std::move(optImprovedParameters),
        core::AuthenticationPayloadMode::File
    );
    const crypto::OpenSslSecureRandomProvider rngProvider;
    core::AuthenticationAuthority autAuthority(rngProvider);
    const core::SenderAuthenticationMaterial matMaterial =
        autAuthority.matIssueSenderMaterial("FILE-SENDER", prmRound);

    ResultCollector colSenderResults;
    ResultCollector colReceiverResults;
    std::mutex mtxPersistedFile;
    std::vector<std::uint8_t> vecPersistedFile;
    core::AuthenticationNodeRuntime* pReceiver = nullptr;
    core::AuthenticationNodeRuntime runReceiver(
        "FILE-RECEIVER",
        [](const protocol::ByteBuffer&)
        {
            return false;
        },
        [&colReceiverResults](const protocol::NodeControlMessage& msgMessage)
        {
            colReceiverResults.add(msgMessage);
        },
        []()
        {
            return core::TimeSynchronizationStatus(
                true,
                2,
                "Stage 7 test clock is synchronized"
            );
        },
        [
            &mtxPersistedFile,
            &vecPersistedFile,
            bPersistenceAccepted
        ](
            const std::string&,
            const std::string&,
            std::uint64_t,
            const protocol::ByteBuffer& vecRecovered
        )
        {
            std::lock_guard<std::mutex> lckFile(mtxPersistedFile);
            vecPersistedFile = vecRecovered;
            return bPersistenceAccepted;
        }
    );
    pReceiver = &runReceiver;

    core::AuthenticationNodeRuntime runSender(
        "FILE-SENDER",
        [pReceiver](const protocol::ByteBuffer& vecDatagram)
        {
            static_cast<void>(pReceiver->bHandleDatagram(
                "10.0.0.1",
                vecDatagram,
                u64NowMilliseconds()
            ));
            return true;
        },
        [&colSenderResults](const protocol::NodeControlMessage& msgMessage)
        {
            colSenderResults.add(msgMessage);
        },
        []()
        {
            return core::TimeSynchronizationStatus(
                true,
                2,
                "Stage 7 test clock is synchronized"
            );
        }
    );

    const protocol::NodeControlMessage msgSenderConfig(
        protocol::SenderAuthenticationConfigControlDetails(
            "file-sender-config",
            matMaterial.strSenderId(),
            matMaterial.u64ChainId(),
            arrBlock(matMaterial.vecChainSeed()),
            arrBlock(matMaterial.digCommitmentKey()),
            prmControl(matMaterial.prmRoundParameters())
        )
    );
    const protocol::NodeControlMessage msgReceiverConfig(
        protocol::ReceiverAuthenticationContextsControlDetails(
            "file-receiver-config",
            {
                protocol::ReceiverAuthenticationContextControlDetails(
                    matMaterial.strSenderId(),
                    "10.0.0.1",
                    matMaterial.u64ChainId(),
                    arrBlock(matMaterial.digCommitmentKey()),
                    prmControl(matMaterial.prmRoundParameters()),
                    protocol::FileReceiverPayloadControlDetails(
                        vecOriginal.size()
                    )
                )
            }
        )
    );
    if (!bConfigAccepted(
            runSender.msgHandleControl(
                protocol::TcpClientRole::Manager,
                msgSenderConfig
            ),
            protocol::AuthenticationConfigTarget::Sender
        )
        || !bConfigAccepted(
            runSender.msgApplyFilePayload(
                protocol::TcpClientRole::Manager,
                "file-payload",
                matMaterial.u64ChainId(),
                workload::FileWorkload(vecOriginal)
            ),
            protocol::AuthenticationConfigTarget::FilePayload
        )
        || !bConfigAccepted(
            runReceiver.msgHandleControl(
                protocol::TcpClientRole::Manager,
                msgReceiverConfig
            ),
            protocol::AuthenticationConfigTarget::Receiver
        ))
    {
        return false;
    }

    const std::string strRoundId = modeAuthentication
            == core::TeslaAuthenticationMode::Native
        ? "native-file-round"
        : "improved-file-round";
    const std::uint64_t u64StartTimestamp = u64NowMilliseconds() + 350U;
    const auto fnStartMessage = [
        &strRoundId,
        u64StartTimestamp
    ](const std::string& strRequestId)
    {
        return protocol::NodeControlMessage(
            protocol::AuthenticationRoundCommandControlDetails(
                strRequestId,
                strRoundId,
                protocol::AuthenticationRoundCommand::Start,
                u64StartTimestamp,
                1
            )
        );
    };
    if (!bRoundAccepted(runReceiver.msgHandleControl(
            protocol::TcpClientRole::Manager,
            fnStartMessage("start-file-receiver")
        ))
        || !bRoundAccepted(runSender.msgHandleControl(
            protocol::TcpClientRole::Manager,
            fnStartMessage("start-file-sender")
        )))
    {
        return false;
    }

    const bool bResultsReady =
        colSenderResults.bWait(std::chrono::seconds(5))
        && colReceiverResults.bWait(std::chrono::seconds(5));
    runSender.stop();
    runReceiver.stop();
    if (!bResultsReady)
    {
        return false;
    }

    const auto detSender = colSenderResults.detFirst();
    const auto detReceiver = colReceiverResults.detFirst();
    if (detSender.statusResult()
            != protocol::AuthenticationRoundResultStatus::Completed
        || !std::holds_alternative<
            protocol::FileSenderAuthenticationRoundResultDetails
        >(detSender.varResultDetails())
        || !std::holds_alternative<
            protocol::FileReceiverAuthenticationRoundResultDetails
        >(detReceiver.varResultDetails()))
    {
        return false;
    }

    const auto& detFile = std::get<
        protocol::FileReceiverAuthenticationRoundResultDetails
    >(detReceiver.varResultDetails());
    const crypto::OpenSslCryptoProvider crpSha256(
        crypto::CryptoAlgorithm::Sha256
    );
    const crypto::Digest digOriginalSha256 = crpSha256.digHash(vecOriginal);
    {
        std::lock_guard<std::mutex> lckFile(mtxPersistedFile);
        if (vecPersistedFile != vecOriginal)
        {
            return false;
        }
    }

    const protocol::AuthenticationRoundResultStatus stsExpected =
        bPersistenceAccepted
        ? protocol::AuthenticationRoundResultStatus::Completed
        : protocol::AuthenticationRoundResultStatus::ProtocolIncomplete;
    return detReceiver.statusResult() == stsExpected
        && detReceiver.u32AuthenticatedPacketCount() == 3
        && detReceiver.u32FailedPacketCount() == 0
        && detReceiver.u32MissingPacketCount() == 0
        && detFile.u64OriginalByteCount() == vecOriginal.size()
        && detFile.u64RecoveredByteCount() == vecOriginal.size()
        && detFile.optRecoveredSha256().has_value()
        && detFile.optRecoveredSha256().value() == arrBlock(digOriginalSha256);
}
}

int main()
{
    try
    {
        if (!bCheckWorkloadBoundaries())
        {
            std::cerr << "FAILED: file slicing or recovery boundary." << std::endl;
            return 1;
        }
        if (!bCheckUploadSession())
        {
            std::cerr << "FAILED: bounded TCP file upload session." << std::endl;
            return 1;
        }
        if (!bCheckFileProtocolVariants())
        {
            std::cerr << "FAILED: file protocol variant or secret boundary." << std::endl;
            return 1;
        }
        if (!bRunFileRound(
                core::TeslaAuthenticationMode::Native,
                crypto::CryptoAlgorithm::Sha256,
                true
            ))
        {
            std::cerr << "FAILED: native file authentication round." << std::endl;
            return 1;
        }
        if (!bRunFileRound(
                core::TeslaAuthenticationMode::Improved,
                crypto::CryptoAlgorithm::Sm3,
                true
            ))
        {
            std::cerr << "FAILED: improved file authentication round." << std::endl;
            return 1;
        }
        if (!bRunFileRound(
                core::TeslaAuthenticationMode::Native,
                crypto::CryptoAlgorithm::Sha3_256,
                false
            ))
        {
            std::cerr << "FAILED: persistence failure did not downgrade result."
                      << std::endl;
            return 1;
        }

        std::cout
            << "Stage 7 file slicing, upload, authentication, recovery and Hash passed."
            << std::endl;
        return 0;
    }
    catch (const std::exception& exError)
    {
        std::cerr << "FAILED: " << exError.what() << std::endl;
        return 1;
    }
}
