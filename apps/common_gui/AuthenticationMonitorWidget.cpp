#include "AuthenticationMonitorWidget.h"

#include "tesla/protocol/AuthenticationControl.h"

#include <QAbstractTableModel>
#include <QButtonGroup>
#include <QColor>
#include <QComboBox>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QTabWidget>
#include <QTableView>
#include <QTextEdit>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <utility>
#include <variant>

namespace tesla::gui
{
namespace
{
using namespace protocol;
using namespace metrics;

QString strHex(const ByteBuffer& vecBytes)
{
    static constexpr char HEX[] = "0123456789abcdef";
    QString strValue;
    strValue.reserve(static_cast<qsizetype>(vecBytes.size() * 2U));
    for (const std::uint8_t u8Value : vecBytes)
    {
        strValue.append(QLatin1Char(HEX[(u8Value >> 4U) & 0x0FU]));
        strValue.append(QLatin1Char(HEX[u8Value & 0x0FU]));
    }
    return strValue;
}

QString strCsv(const QString& strValue)
{
    QString strEscaped = strValue;
    strEscaped.replace(QLatin1Char('"'), QStringLiteral("\"\""));
    return QLatin1Char('"') + strEscaped + QLatin1Char('"');
}

QString strMetricMode(AuthenticationMetricMode modeAuthentication)
{
    return modeAuthentication == AuthenticationMetricMode::Native
        ? QStringLiteral("NATIVE")
        : QStringLiteral("IMPROVED");
}

QString strBlock(const BinaryBlock& arrValue)
{
    return strHex(ByteBuffer(arrValue.begin(), arrValue.end()));
}

QString strTime(std::uint64_t u64TimestampMilliseconds)
{
    return QDateTime::fromMSecsSinceEpoch(
        static_cast<qint64>(u64TimestampMilliseconds)
    ).toString(QStringLiteral("HH:mm:ss.zzz"));
}

QString strPacketStatus(PacketAuthenticationStatus statusAuthentication)
{
    switch (statusAuthentication)
    {
    case PacketAuthenticationStatus::Generated:
        return QStringLiteral("GENERATED");
    case PacketAuthenticationStatus::Pending:
        return QStringLiteral("PENDING");
    case PacketAuthenticationStatus::Passed:
        return QStringLiteral("PASS");
    case PacketAuthenticationStatus::Failed:
        return QStringLiteral("FAIL");
    }
    return QStringLiteral("UNKNOWN");
}

QString strFailureType(AuthenticationFailureType typeFailure)
{
    switch (typeFailure)
    {
    case AuthenticationFailureType::MacFailed:
        return QStringLiteral("MAC_FAILED");
    case AuthenticationFailureType::TamperedVariant:
        return QStringLiteral("TAMPERED_VARIANT");
    case AuthenticationFailureType::FastGroupFailed:
        return QStringLiteral("FAST_GROUP_FAILED");
    case AuthenticationFailureType::GroupTauFailed:
        return QStringLiteral("GROUP_TAU_FAILED");
    case AuthenticationFailureType::DetectionThresholdExceeded:
        return QStringLiteral("DETECTION_THRESHOLD_EXCEEDED");
    case AuthenticationFailureType::ReplayDuplicate:
        return QStringLiteral("REPLAY_DUPLICATE");
    case AuthenticationFailureType::ReplayLate:
        return QStringLiteral("REPLAY_LATE");
    case AuthenticationFailureType::ReplayExpiredChain:
        return QStringLiteral("REPLAY_EXPIRED_CHAIN");
    case AuthenticationFailureType::MissingPacket:
        return QStringLiteral("MISSING_PACKET");
    case AuthenticationFailureType::IncompleteGroupTags:
        return QStringLiteral("INCOMPLETE_GROUP_TAGS");
    case AuthenticationFailureType::UnverifiableMissingBaseline:
        return QStringLiteral("UNVERIFIABLE_MISSING_BASELINE");
    case AuthenticationFailureType::UnknownContext:
        return QStringLiteral("UNKNOWN_CONTEXT");
    case AuthenticationFailureType::ProtocolError:
        return QStringLiteral("PROTOCOL_ERROR");
    case AuthenticationFailureType::InvalidSchedulingOverrun:
        return QStringLiteral("INVALID_SCHEDULING_OVERRUN");
    case AuthenticationFailureType::AbnormalRecordLimitReached:
        return QStringLiteral("ABNORMAL_RECORD_LIMIT_REACHED");
    }
    return QStringLiteral("UNKNOWN");
}

QString strAlgorithm(AuthenticationCryptoAlgorithm algCrypto)
{
    switch (algCrypto)
    {
    case AuthenticationCryptoAlgorithm::Sha256:
        return QStringLiteral("SHA-256");
    case AuthenticationCryptoAlgorithm::Sm3:
        return QStringLiteral("SM3");
    case AuthenticationCryptoAlgorithm::Sha3_256:
        return QStringLiteral("SHA3-256");
    }
    return QStringLiteral("UNKNOWN");
}

QString strMode(UdpAuthenticationMode modeAuthentication)
{
    return modeAuthentication == UdpAuthenticationMode::Native
        ? QStringLiteral("原生TESLA")
        : QStringLiteral("改进TESLA");
}

QString strSource(PacketSourceType typeSource)
{
    switch (typeSource)
    {
    case PacketSourceType::NormalSender:
        return QStringLiteral("正常Sender");
    case PacketSourceType::AttackInjection:
        return QStringLiteral("攻击注入");
    case PacketSourceType::UnknownSource:
        return QStringLiteral("未知来源");
    }
    return QStringLiteral("未知");
}

bool bIsReplay(AuthenticationFailureType typeFailure)
{
    return typeFailure == AuthenticationFailureType::ReplayDuplicate
        || typeFailure == AuthenticationFailureType::ReplayLate
        || typeFailure == AuthenticationFailureType::ReplayExpiredChain;
}

class PacketTableModel final : public QAbstractTableModel
{
public:
    explicit PacketTableModel(QObject* pParent = nullptr)
        : QAbstractTableModel(pParent)
    {
    }

    int rowCount(const QModelIndex& = QModelIndex()) const override
    {
        return static_cast<int>(m_vecPackets.size());
    }

    int columnCount(const QModelIndex& = QModelIndex()) const override
    {
        return 13;
    }

    QVariant headerData(
        int nSection,
        Qt::Orientation oriOrientation,
        int nRole
    ) const override
    {
        if (oriOrientation != Qt::Horizontal || nRole != Qt::DisplayRole)
        {
            return {};
        }
        static const std::array<const char*, 13> HEADERS{
            "时间", "Sender", "Chain ID", "方向", "对端/源IP", "来源",
            "类型", "报文编号", "间隔", "密钥编号", "长度", "MAC/标签",
            "结果"
        };
        return QString::fromUtf8(HEADERS.at(static_cast<std::size_t>(nSection)));
    }

    QVariant data(const QModelIndex& idxIndex, int nRole) const override
    {
        if (!idxIndex.isValid()
            || idxIndex.row() < 0
            || idxIndex.row() >= rowCount())
        {
            return {};
        }
        const auto& detPacket = m_vecPackets.at(
            static_cast<std::size_t>(idxIndex.row())
        );
        if (nRole == Qt::UserRole)
        {
            return QVariant::fromValue<qulonglong>(detPacket.u64EventId());
        }
        if (nRole == Qt::BackgroundRole
            && (detPacket.statusAuthentication()
                    == PacketAuthenticationStatus::Failed
                || detPacket.typeSource() != PacketSourceType::NormalSender))
        {
            return QColor(255, 226, 226);
        }
        if (nRole != Qt::DisplayRole)
        {
            return {};
        }

        switch (idxIndex.column())
        {
        case 0:
            return strTime(detPacket.u64TimestampMilliseconds());
        case 1:
            return QString::fromStdString(detPacket.strSenderId());
        case 2:
            return QString::number(detPacket.u64ChainId());
        case 3:
            return detPacket.dirDirection() == PacketObservationDirection::Tx
                ? QStringLiteral("TX") : QStringLiteral("RX");
        case 4:
            return QString::fromStdString(
                detPacket.strActualSourceIp().empty()
                    ? detPacket.strPeer()
                    : detPacket.strActualSourceIp()
            );
        case 5:
            return strSource(detPacket.typeSource());
        case 6:
            return std::holds_alternative<DisclosurePacketObservationDetails>(
                detPacket.varPayloadDetails()
            ) ? QStringLiteral("DISCLOSE") : QStringLiteral("DATA");
        case 7:
            return QString::number(detPacket.u32PacketIndex());
        case 8:
            return QString::number(detPacket.u32IntervalIndex());
        case 9:
        {
            const std::uint32_t u32DisclosedKeyIndex =
                detPacket.u32IntervalIndex() > detPacket.u32DisclosureDelay()
                ? detPacket.u32IntervalIndex()
                    - detPacket.u32DisclosureDelay()
                : 0;
            if (std::holds_alternative<DisclosurePacketObservationDetails>(
                    detPacket.varPayloadDetails()
                ))
            {
                return QStringLiteral("披露K%1").arg(u32DisclosedKeyIndex);
            }
            const auto& detData = std::get<DataPacketObservationDetails>(
                detPacket.varPayloadDetails()
            );
            return detData.optDisclosedKey().has_value()
                ? QStringLiteral("K%1 / 披露K%2")
                    .arg(detPacket.u32IntervalIndex())
                    .arg(u32DisclosedKeyIndex)
                : QStringLiteral("K%1").arg(detPacket.u32IntervalIndex());
        }
        case 10:
            return QStringLiteral("%1 B").arg(static_cast<qulonglong>(
                detPacket.vecRawDatagram().size()
            ));
        case 11:
            return detPacket.modeAuthentication()
                == UdpAuthenticationMode::Native
                ? QStringLiteral("MAC") : QStringLiteral("τ/组标签");
        case 12:
            return strPacketStatus(detPacket.statusAuthentication());
        default:
            return {};
        }
    }

    void setPackets(std::vector<PacketObservationControlDetails> vecPackets)
    {
        beginResetModel();
        m_vecPackets = std::move(vecPackets);
        endResetModel();
    }

    const PacketObservationControlDetails* pPacket(int nRow) const
    {
        return nRow >= 0 && nRow < rowCount()
            ? &m_vecPackets.at(static_cast<std::size_t>(nRow))
            : nullptr;
    }

    int nRowForEventId(std::uint64_t u64EventId) const
    {
        for (std::size_t nIndex = 0; nIndex < m_vecPackets.size(); ++nIndex)
        {
            if (m_vecPackets[nIndex].u64EventId() == u64EventId)
            {
                return static_cast<int>(nIndex);
            }
        }
        return -1;
    }

private:
    std::vector<PacketObservationControlDetails> m_vecPackets;
};

class FailureTableModel final : public QAbstractTableModel
{
public:
    explicit FailureTableModel(QObject* pParent = nullptr)
        : QAbstractTableModel(pParent)
    {
    }

    int rowCount(const QModelIndex& = QModelIndex()) const override
    {
        return static_cast<int>(m_vecFailures.size());
    }

    int columnCount(const QModelIndex& = QModelIndex()) const override
    {
        return 8;
    }

    QVariant headerData(int nSection, Qt::Orientation ori, int nRole) const override
    {
        if (ori != Qt::Horizontal || nRole != Qt::DisplayRole)
        {
            return {};
        }
        static const std::array<const char*, 8> HEADERS{
            "时间", "Sender", "Chain ID", "报文编号", "分组", "异常类型",
            "失败摘要", "实际源IP"
        };
        return QString::fromUtf8(HEADERS.at(static_cast<std::size_t>(nSection)));
    }

    QVariant data(const QModelIndex& idxIndex, int nRole) const override
    {
        if (!idxIndex.isValid()
            || idxIndex.row() < 0
            || idxIndex.row() >= rowCount())
        {
            return {};
        }
        const auto& detFailure = m_vecFailures.at(
            static_cast<std::size_t>(idxIndex.row())
        );
        if (nRole == Qt::BackgroundRole)
        {
            return detFailure.sevSeverity() == ObservationSeverity::Error
                ? QColor(255, 226, 226) : QColor(255, 244, 204);
        }
        if (nRole != Qt::DisplayRole)
        {
            return {};
        }
        switch (idxIndex.column())
        {
        case 0:
            return strTime(detFailure.u64TimestampMilliseconds());
        case 1:
            return QString::fromStdString(detFailure.strSenderId());
        case 2:
            return QString::number(detFailure.u64ChainId());
        case 3:
            return QString::number(detFailure.u32PacketIndex());
        case 4:
            return detFailure.optGroupIndex().has_value()
                ? QString::number(detFailure.optGroupIndex().value())
                : QStringLiteral("—");
        case 5:
            return strFailureType(detFailure.typeFailure());
        case 6:
            return QString::fromStdString(detFailure.strReason());
        case 7:
            return detFailure.strActualSourceIp().empty()
                ? QStringLiteral("—")
                : QString::fromStdString(detFailure.strActualSourceIp());
        default:
            return {};
        }
    }

    void setFailures(std::vector<PacketFailureControlDetails> vecFailures)
    {
        beginResetModel();
        m_vecFailures = std::move(vecFailures);
        endResetModel();
    }

    const PacketFailureControlDetails* pFailure(int nRow) const
    {
        return nRow >= 0 && nRow < rowCount()
            ? &m_vecFailures.at(static_cast<std::size_t>(nRow))
            : nullptr;
    }

    const std::vector<PacketFailureControlDetails>& vecFailures() const
    {
        return m_vecFailures;
    }

private:
    std::vector<PacketFailureControlDetails> m_vecFailures;
};

enum class QuickFilter
{
    All,
    Abnormal,
    Mac,
    FastGroup,
    Tau,
    Replay,
    Protocol,
    Missing
};

class PacketFilterProxyModel final : public QSortFilterProxyModel
{
public:
    explicit PacketFilterProxyModel(QObject* pParent = nullptr)
        : QSortFilterProxyModel(pParent)
    {
    }

    void setFailures(const std::vector<PacketFailureControlDetails>& vecFailures)
    {
        m_mapFailures.clear();
        for (const auto& detFailure : vecFailures)
        {
            if (detFailure.u64PacketEventId() != 0)
            {
                m_mapFailures[detFailure.u64PacketEventId()].push_back(
                    detFailure.typeFailure()
                );
            }
        }
        invalidateFilter();
    }

    void setQuickFilter(QuickFilter fltQuick)
    {
        m_fltQuick = fltQuick;
        invalidateFilter();
    }

    void setQuery(
        QString strSender,
        QString strChain,
        QString strPacket,
        QString strInterval,
        QString strSource,
        QString strStatus
    )
    {
        m_strSender = strSender.trimmed();
        m_strChain = strChain.trimmed();
        m_strPacket = strPacket.trimmed();
        m_strInterval = strInterval.trimmed();
        m_strSource = strSource.trimmed();
        m_strStatus = strStatus.trimmed();
        invalidateFilter();
    }

protected:
    bool filterAcceptsRow(int nSourceRow, const QModelIndex&) const override
    {
        const auto* pModel = static_cast<const PacketTableModel*>(sourceModel());
        const auto* pPacket = pModel == nullptr
            ? nullptr : pModel->pPacket(nSourceRow);
        if (pPacket == nullptr)
        {
            return false;
        }

        if (!m_strSender.isEmpty()
            && QString::fromStdString(pPacket->strSenderId()) != m_strSender)
        {
            return false;
        }
        if (!m_strChain.isEmpty()
            && QString::number(pPacket->u64ChainId()) != m_strChain)
        {
            return false;
        }
        if (!m_strPacket.isEmpty()
            && QString::number(pPacket->u32PacketIndex()) != m_strPacket)
        {
            return false;
        }
        if (!m_strInterval.isEmpty()
            && QString::number(pPacket->u32IntervalIndex()) != m_strInterval)
        {
            return false;
        }
        if (!m_strSource.isEmpty()
            && !QString::fromStdString(pPacket->strActualSourceIp()).contains(
                m_strSource,
                Qt::CaseInsensitive
            ))
        {
            return false;
        }
        if (!m_strStatus.isEmpty()
            && m_strStatus != QStringLiteral("全部")
            && strPacketStatus(pPacket->statusAuthentication()) != m_strStatus)
        {
            return false;
        }

        if (m_fltQuick == QuickFilter::All)
        {
            return true;
        }
        const auto itFailures = m_mapFailures.find(pPacket->u64EventId());
        if (itFailures == m_mapFailures.end())
        {
            return false;
        }
        if (m_fltQuick == QuickFilter::Abnormal)
        {
            return true;
        }
        return std::any_of(
            itFailures->second.begin(),
            itFailures->second.end(),
            [this](AuthenticationFailureType typeFailure)
            {
                switch (m_fltQuick)
                {
                case QuickFilter::Mac:
                    return typeFailure == AuthenticationFailureType::MacFailed
                        || typeFailure
                            == AuthenticationFailureType::TamperedVariant;
                case QuickFilter::FastGroup:
                    return typeFailure
                        == AuthenticationFailureType::FastGroupFailed;
                case QuickFilter::Tau:
                    return typeFailure
                        == AuthenticationFailureType::GroupTauFailed;
                case QuickFilter::Replay:
                    return bIsReplay(typeFailure);
                case QuickFilter::Protocol:
                    return typeFailure
                            == AuthenticationFailureType::ProtocolError
                        || typeFailure
                            == AuthenticationFailureType::UnknownContext;
                case QuickFilter::Missing:
                    return typeFailure
                            == AuthenticationFailureType::MissingPacket
                        || typeFailure
                            == AuthenticationFailureType::IncompleteGroupTags
                        || typeFailure
                            == AuthenticationFailureType::UnverifiableMissingBaseline;
                default:
                    return true;
                }
            }
        );
    }

private:
    std::map<std::uint64_t, std::vector<AuthenticationFailureType>> m_mapFailures;
    QuickFilter m_fltQuick{QuickFilter::All};
    QString m_strSender;
    QString m_strChain;
    QString m_strPacket;
    QString m_strInterval;
    QString m_strSource;
    QString m_strStatus;
};

QString strPacketDetails(const PacketObservationControlDetails& detPacket)
{
    const std::uint32_t u32DisclosedKeyIndex =
        detPacket.u32IntervalIndex() > detPacket.u32DisclosureDelay()
        ? detPacket.u32IntervalIndex() - detPacket.u32DisclosureDelay()
        : 0;
    QStringList lstLines{
        QStringLiteral("Event ID: %1").arg(detPacket.u64EventId()),
        QStringLiteral("时间: %1").arg(strTime(detPacket.u64TimestampMilliseconds())),
        QStringLiteral("逻辑Sender ID: %1").arg(QString::fromStdString(detPacket.strSenderId())),
        QStringLiteral("Sender IP: %1").arg(QString::fromStdString(detPacket.strSenderIp())),
        QStringLiteral("实际UDP源IP: %1").arg(QString::fromStdString(detPacket.strActualSourceIp())),
        QStringLiteral("对端: %1").arg(QString::fromStdString(detPacket.strPeer())),
        QStringLiteral("来源类型: %1").arg(strSource(detPacket.typeSource())),
        QStringLiteral("Chain ID: %1").arg(detPacket.u64ChainId()),
        QStringLiteral("间隔编号: %1").arg(detPacket.u32IntervalIndex()),
        QStringLiteral("全局报文编号: %1").arg(detPacket.u32PacketIndex()),
        QStringLiteral("每间隔发包数: %1").arg(detPacket.u32PacketsPerInterval()),
        QStringLiteral("披露延迟: %1").arg(detPacket.u32DisclosureDelay()),
        QStringLiteral("认证模式: %1").arg(strMode(detPacket.modeAuthentication())),
        QStringLiteral("密码算法: %1").arg(strAlgorithm(detPacket.algCryptoAlgorithm())),
        QStringLiteral("状态: %1").arg(strPacketStatus(detPacket.statusAuthentication())),
        QStringLiteral("候选Hash: %1").arg(QString::fromStdString(detPacket.strCandidateHash())),
        QStringLiteral("重复次数: %1").arg(detPacket.u32DuplicateCount()),
        QStringLiteral("原因: %1").arg(QString::fromStdString(detPacket.strReason()))
    };

    if (const auto* pDisclosure = std::get_if<DisclosurePacketObservationDetails>(
            &detPacket.varPayloadDetails()
        ))
    {
        lstLines << QStringLiteral("类型: DISCLOSE")
                 << QStringLiteral("披露密钥编号: K%1").arg(
                        u32DisclosedKeyIndex
                    )
                 << QStringLiteral("披露Key: %1").arg(
                        strBlock(pDisclosure->arrDisclosedKey())
                    );
    }
    else
    {
        const auto& detData = std::get<DataPacketObservationDetails>(
            detPacket.varPayloadDetails()
        );
        lstLines << QStringLiteral("类型: DATA")
                 << QStringLiteral("数据密钥编号: K%1").arg(
                        detPacket.u32IntervalIndex()
                    )
                 << QStringLiteral("Message: %1").arg(
                        strBlock(detData.arrMessage())
                    );
        if (detData.optDisclosedKey().has_value())
        {
            lstLines << QStringLiteral("披露密钥编号: K%1").arg(
                u32DisclosedKeyIndex
            );
            lstLines << QStringLiteral("携带披露Key: %1").arg(
                strBlock(detData.optDisclosedKey().value())
            );
        }
        if (const auto* pNative = std::get_if<NativePacketObservationDetails>(
                &detData.varModeDetails()
            ))
        {
            lstLines << QStringLiteral("MAC: %1").arg(
                strBlock(pNative->arrPacketMac())
            );
        }
        else
        {
            const auto& detImproved = std::get<ImprovedPacketObservationDetails>(
                detData.varModeDetails()
            );
            for (std::size_t nIndex = 0;
                 nIndex < detImproved.vecSamdTau().size();
                 ++nIndex)
            {
                lstLines << QStringLiteral("τ[%1]: %2")
                    .arg(nIndex)
                    .arg(strBlock(detImproved.vecSamdTau()[nIndex]));
            }
            lstLines << QStringLiteral("FastGroupTag: %1").arg(
                detImproved.optFastGroupTag().has_value()
                    ? strBlock(detImproved.optFastGroupTag().value())
                    : QStringLiteral("本报文不携带")
            );
        }
    }
    lstLines << QStringLiteral("原始UDP字节(%1B): %2")
        .arg(static_cast<qulonglong>(detPacket.vecRawDatagram().size()))
        .arg(strHex(detPacket.vecRawDatagram()));
    return lstLines.join(QLatin1Char('\n'));
}

QString strFailureDetails(const PacketFailureControlDetails& detFailure)
{
    QStringList lstLines{
        QStringLiteral("异常类型: %1").arg(strFailureType(detFailure.typeFailure())),
        QStringLiteral("Sender: %1").arg(QString::fromStdString(detFailure.strSenderId())),
        QStringLiteral("Chain ID: %1").arg(detFailure.u64ChainId()),
        QStringLiteral("预期报文编号: %1").arg(detFailure.u32PacketIndex()),
        QStringLiteral("预期间隔编号: %1").arg(detFailure.u32IntervalIndex()),
        QStringLiteral("实际源IP: %1").arg(
            detFailure.strActualSourceIp().empty()
                ? QStringLiteral("—")
                : QString::fromStdString(detFailure.strActualSourceIp())
        ),
        QStringLiteral("失败原因: %1").arg(QString::fromStdString(detFailure.strReason()))
    };
    if (detFailure.u64PacketEventId() == 0)
    {
        lstLines << QStringLiteral("未收到报文；不存在Message、认证字段或原始UDP数据。");
    }
    if (!detFailure.vecLocatedPacketIndexes().empty())
    {
        QStringList lstIndexes;
        for (const auto u32Index : detFailure.vecLocatedPacketIndexes())
        {
            lstIndexes << QString::number(u32Index);
        }
        lstLines << QStringLiteral("定位出的坏包编号: %1").arg(
            lstIndexes.join(QStringLiteral(", "))
        );
    }
    return lstLines.join(QLatin1Char('\n'));
}
}

class AuthenticationMonitorWidget::Impl final
{
public:
    explicit Impl(AuthenticationMonitorWidget* pOwner)
        : m_pOwner(pOwner),
          m_pPacketModel(new PacketTableModel(pOwner)),
          m_pFailureModel(new FailureTableModel(pOwner)),
          m_pProxyModel(new PacketFilterProxyModel(pOwner)),
          m_pTabs(new QTabWidget(pOwner)),
          m_pPacketTable(new QTableView(pOwner)),
          m_pFailureTable(new QTableView(pOwner)),
          m_pLogTable(new QTableView(pOwner)),
          m_pDetailEdit(new QTextEdit(pOwner)),
          m_pSenderEdit(new QLineEdit(pOwner)),
          m_pChainEdit(new QLineEdit(pOwner)),
          m_pPacketEdit(new QLineEdit(pOwner)),
          m_pIntervalEdit(new QLineEdit(pOwner)),
          m_pSourceEdit(new QLineEdit(pOwner)),
          m_pStatusCombo(new QComboBox(pOwner)),
          m_pDosLabel(new QLabel(pOwner))
    {
        m_pProxyModel->setSourceModel(m_pPacketModel);
        m_pProxyModel->setDynamicSortFilter(true);
        m_pPacketTable->setModel(m_pProxyModel);
        m_pFailureTable->setModel(m_pFailureModel);
        m_pLogTable->setModel(m_pFailureModel);
        m_pDetailEdit->setReadOnly(true);
        m_pDetailEdit->setLineWrapMode(QTextEdit::NoWrap);
        m_pStatusCombo->addItems({
            QStringLiteral("全部"),
            QStringLiteral("PASS"),
            QStringLiteral("PENDING"),
            QStringLiteral("FAIL"),
            QStringLiteral("GENERATED")
        });
        createPages();
        connectActions();
    }

    void setSnapshots(
        std::vector<PacketObservationControlDetails> vecPackets,
        std::vector<PacketFailureControlDetails> vecFailures,
        std::vector<DosSummaryControlDetails> vecDosSummaries
    )
    {
        m_vecPackets = vecPackets;
        m_vecFailures = vecFailures;
        m_vecDosSummaries = vecDosSummaries;
        m_pPacketModel->setPackets(std::move(vecPackets));
        m_pFailureModel->setFailures(std::move(vecFailures));
        m_pProxyModel->setFailures(m_pFailureModel->vecFailures());
        refreshQuickButtonCounts();

        if (vecDosSummaries.empty())
        {
            m_pDosLabel->setText(QStringLiteral("DoS汇总：暂无"));
        }
        else
        {
            const auto& detSummary = vecDosSummaries.back();
            m_pDosLabel->setText(QStringLiteral(
                "最近%1毫秒：无效报文=%2，限速丢弃=%3，合法报文=%4，队列溢出=%5"
            )
                .arg(detSummary.u32WindowMilliseconds())
                .arg(detSummary.u64InvalidPacketCount())
                .arg(detSummary.u64RateLimitedDropCount())
                .arg(detSummary.u64LegitimatePacketCount())
                .arg(detSummary.u64ReceiveQueueOverflowCount()));
        }
    }

    void setMetricSnapshots(
        std::vector<AuthenticationMetricRecord> vecMetrics
    )
    {
        m_vecRoundArchives.clear();
        for (AuthenticationMetricRecord& varMetric : vecMetrics)
        {
            if (auto* pArchive = std::get_if<
                    AuthenticationRoundArchiveSummary
                >(&varMetric))
            {
                m_vecRoundArchives.push_back(std::move(*pArchive));
            }
        }
    }

private:
    void exportRoundArchives(bool bJson)
    {
        if (m_vecRoundArchives.empty())
        {
            QMessageBox::information(
                m_pOwner,
                QStringLiteral("导出逐轮记录"),
                QStringLiteral("当前没有已经结束的逐轮归档记录。")
            );
            return;
        }

        const QString strSuffix = bJson
            ? QStringLiteral("json")
            : QStringLiteral("csv");
        const QString strPath = QFileDialog::getSaveFileName(
            m_pOwner,
            QStringLiteral("导出本节点逐轮记录"),
            QStringLiteral("tesla-round-records-%1.%2")
                .arg(
                    QDateTime::currentDateTime().toString(
                        QStringLiteral("yyyyMMdd-HHmmss")
                    ),
                    strSuffix
                ),
            bJson ? QStringLiteral("JSON (*.json)") : QStringLiteral("CSV (*.csv)")
        );
        if (strPath.isEmpty())
        {
            return;
        }

        static const QString strCsvHeader = QStringLiteral(
            "experimentId,runId,timestamp,gitCommit,nodeId,senderId,chainId,role,"
            "authMode,cryptoAlgorithm,payloadHash,packetCount,packetsPerInterval,"
            "intervalMs,disclosureDelay,groupSize,detectionThreshold,randomSeed,"
            "configuredFault,configuredFaultValue,sentPackets,receivedPackets,"
            "authenticatedPackets,failedPackets,missingPackets,fallbackGroupCount,"
            "verifyTimeUs,receivedAuthBytes,estimatedEnergyMicroJoule,fileSize,"
            "recoveredFileSize,recoveredFileHash,roundStatus,validSample,invalidReason\r\n"
        );
        QByteArray arrOutput;
        QJsonArray arrJsonRecords;
        if (!bJson)
        {
            arrOutput.append(strCsvHeader.toUtf8());
        }

        for (const AuthenticationRoundArchiveSummary& sumArchive
            : m_vecRoundArchives)
        {
            const AuthenticationRoundArchiveConfiguration& cfgArchive =
                sumArchive.cfgConfiguration();
            const auto* pSender = std::get_if<SenderRoundArchiveDetails>(
                &sumArchive.varDetails()
            );
            const auto* pReceiver = std::get_if<ReceiverRoundArchiveDetails>(
                &sumArchive.varDetails()
            );

            const QString strRole = pSender != nullptr
                ? QStringLiteral("SENDER") : QStringLiteral("RECEIVER");
            const QString strConfiguredFault = pSender != nullptr
                ? QString::fromStdString(pSender->strConfiguredFault())
                : QStringLiteral("NOT_DISTRIBUTED");
            const QString strConfiguredFaultValue = pSender != nullptr
                ? QString::fromStdString(pSender->strConfiguredFaultValue())
                : QString();
            const std::uint64_t u64RandomSeed = pSender != nullptr
                ? pSender->u64RandomSeed() : 0;
            const std::uint32_t u32SentPackets = pSender != nullptr
                ? pSender->u32SentPacketCount() : 0;
            const std::uint32_t u32ReceivedPackets = pReceiver != nullptr
                ? pReceiver->u32ReceivedPacketCount() : 0;
            const std::uint32_t u32AuthenticatedPackets = pReceiver != nullptr
                ? pReceiver->u32AuthenticatedPacketCount() : 0;
            const std::uint32_t u32FailedPackets = pReceiver != nullptr
                ? pReceiver->u32FailedPacketCount() : 0;
            const std::uint32_t u32MissingPackets = pReceiver != nullptr
                ? pReceiver->u32MissingPacketCount() : 0;
            const std::uint32_t u32FallbackGroupCount = pReceiver != nullptr
                ? pReceiver->u32FallbackGroupCount() : 0;
            const std::uint64_t u64VerifyTimeNanoseconds = pReceiver != nullptr
                ? pReceiver->u64VerifyTimeNanoseconds() : 0;
            const std::uint64_t u64ReceivedAuthBytes = pReceiver != nullptr
                ? pReceiver->u64ReceivedAuthBytes() : 0;
            const double dEstimatedEnergyMicroJoule = pReceiver != nullptr
                ? pReceiver->dEstimatedEnergyMicroJoule() : 0.0;
            const std::uint64_t u64FileSize = pSender != nullptr
                ? pSender->u64FileSize()
                : pReceiver->u64FileSize();
            const std::uint64_t u64RecoveredFileSize = pReceiver != nullptr
                ? pReceiver->u64RecoveredFileSize() : 0;
            const QString strRecoveredFileHash = pReceiver != nullptr
                ? QString::fromStdString(pReceiver->strRecoveredFileHash())
                : QString();

            if (bJson)
            {
                QJsonObject objRecord;
                objRecord.insert(QStringLiteral("experimentId"), QString::fromStdString(sumArchive.strExperimentId()));
                objRecord.insert(QStringLiteral("runId"), QString::fromStdString(sumArchive.strRunId()));
                objRecord.insert(QStringLiteral("timestamp"), QString::number(sumArchive.u64TimestampMilliseconds()));
                objRecord.insert(QStringLiteral("gitCommit"), QString::fromStdString(sumArchive.strGitCommit()));
                objRecord.insert(QStringLiteral("nodeId"), QString::fromStdString(sumArchive.strNodeId()));
                objRecord.insert(QStringLiteral("senderId"), QString::fromStdString(sumArchive.strSenderId()));
                objRecord.insert(QStringLiteral("chainId"), QString::number(sumArchive.u64ChainId()));
                objRecord.insert(QStringLiteral("role"), strRole);
                objRecord.insert(QStringLiteral("authMode"), strMetricMode(cfgArchive.modeAuthentication()));
                objRecord.insert(QStringLiteral("cryptoAlgorithm"), QString::fromStdString(cfgArchive.strCryptoAlgorithm()));
                objRecord.insert(QStringLiteral("payloadHash"), QString::fromStdString(cfgArchive.strPayloadHash()));
                objRecord.insert(QStringLiteral("packetCount"), static_cast<qint64>(cfgArchive.u32PacketCount()));
                objRecord.insert(QStringLiteral("packetsPerInterval"), static_cast<qint64>(cfgArchive.u32PacketsPerInterval()));
                objRecord.insert(QStringLiteral("intervalMs"), static_cast<qint64>(cfgArchive.u32IntervalMilliseconds()));
                objRecord.insert(QStringLiteral("disclosureDelay"), static_cast<qint64>(cfgArchive.u32DisclosureDelay()));
                objRecord.insert(QStringLiteral("groupSize"), static_cast<qint64>(cfgArchive.u32GroupSize()));
                objRecord.insert(QStringLiteral("detectionThreshold"), static_cast<qint64>(cfgArchive.u32DetectionThreshold()));
                objRecord.insert(QStringLiteral("randomSeed"), QString::number(u64RandomSeed));
                objRecord.insert(QStringLiteral("configuredFault"), strConfiguredFault);
                objRecord.insert(QStringLiteral("configuredFaultValue"), strConfiguredFaultValue);
                objRecord.insert(QStringLiteral("sentPackets"), static_cast<qint64>(u32SentPackets));
                objRecord.insert(QStringLiteral("receivedPackets"), static_cast<qint64>(u32ReceivedPackets));
                objRecord.insert(QStringLiteral("authenticatedPackets"), static_cast<qint64>(u32AuthenticatedPackets));
                objRecord.insert(QStringLiteral("failedPackets"), static_cast<qint64>(u32FailedPackets));
                objRecord.insert(QStringLiteral("missingPackets"), static_cast<qint64>(u32MissingPackets));
                objRecord.insert(QStringLiteral("fallbackGroupCount"), static_cast<qint64>(u32FallbackGroupCount));
                objRecord.insert(QStringLiteral("verifyTimeUs"), static_cast<double>(u64VerifyTimeNanoseconds) / 1000.0);
                objRecord.insert(QStringLiteral("receivedAuthBytes"), QString::number(u64ReceivedAuthBytes));
                objRecord.insert(QStringLiteral("estimatedEnergyMicroJoule"), dEstimatedEnergyMicroJoule);
                objRecord.insert(QStringLiteral("fileSize"), QString::number(u64FileSize));
                objRecord.insert(QStringLiteral("recoveredFileSize"), QString::number(u64RecoveredFileSize));
                objRecord.insert(QStringLiteral("recoveredFileHash"), strRecoveredFileHash);
                objRecord.insert(QStringLiteral("roundStatus"), QString::fromStdString(sumArchive.strRoundStatus()));
                objRecord.insert(QStringLiteral("validSample"), sumArchive.bValidSample());
                objRecord.insert(QStringLiteral("invalidReason"), QString::fromStdString(sumArchive.strInvalidReason()));
                arrJsonRecords.append(objRecord);
                continue;
            }

            const QStringList lstColumns{
                strCsv(QString::fromStdString(sumArchive.strExperimentId())),
                strCsv(QString::fromStdString(sumArchive.strRunId())),
                QString::number(sumArchive.u64TimestampMilliseconds()),
                strCsv(QString::fromStdString(sumArchive.strGitCommit())),
                strCsv(QString::fromStdString(sumArchive.strNodeId())),
                strCsv(QString::fromStdString(sumArchive.strSenderId())),
                QString::number(sumArchive.u64ChainId()),
                strRole,
                strMetricMode(cfgArchive.modeAuthentication()),
                strCsv(QString::fromStdString(cfgArchive.strCryptoAlgorithm())),
                strCsv(QString::fromStdString(cfgArchive.strPayloadHash())),
                QString::number(cfgArchive.u32PacketCount()),
                QString::number(cfgArchive.u32PacketsPerInterval()),
                QString::number(cfgArchive.u32IntervalMilliseconds()),
                QString::number(cfgArchive.u32DisclosureDelay()),
                QString::number(cfgArchive.u32GroupSize()),
                QString::number(cfgArchive.u32DetectionThreshold()),
                QString::number(u64RandomSeed),
                strCsv(strConfiguredFault),
                strCsv(strConfiguredFaultValue),
                QString::number(u32SentPackets),
                QString::number(u32ReceivedPackets),
                QString::number(u32AuthenticatedPackets),
                QString::number(u32FailedPackets),
                QString::number(u32MissingPackets),
                QString::number(u32FallbackGroupCount),
                QString::number(static_cast<double>(u64VerifyTimeNanoseconds) / 1000.0, 'f', 3),
                QString::number(u64ReceivedAuthBytes),
                QString::number(dEstimatedEnergyMicroJoule, 'f', 9),
                QString::number(u64FileSize),
                QString::number(u64RecoveredFileSize),
                strCsv(strRecoveredFileHash),
                strCsv(QString::fromStdString(sumArchive.strRoundStatus())),
                sumArchive.bValidSample() ? QStringLiteral("true") : QStringLiteral("false"),
                strCsv(QString::fromStdString(sumArchive.strInvalidReason()))
            };
            arrOutput.append(
                (lstColumns.join(QLatin1Char(',')) + QStringLiteral("\r\n")).toUtf8()
            );
        }

        if (bJson)
        {
            QJsonObject objRoot;
            objRoot.insert(QStringLiteral("exportedAtMs"), QString::number(
                QDateTime::currentMSecsSinceEpoch()
            ));
            objRoot.insert(QStringLiteral("roundRecords"), arrJsonRecords);
            arrOutput = QJsonDocument(objRoot).toJson(QJsonDocument::Indented);
        }

        QFile filOutput(strPath);
        if (!filOutput.open(QIODevice::WriteOnly | QIODevice::Truncate)
            || filOutput.write(arrOutput) != arrOutput.size())
        {
            QMessageBox::warning(
                m_pOwner,
                QStringLiteral("导出失败"),
                filOutput.errorString()
            );
            return;
        }

        QMessageBox::information(
            m_pOwner,
            QStringLiteral("导出完成"),
            QStringLiteral("已导出 %1 条本节点逐轮记录。")
                .arg(static_cast<qulonglong>(m_vecRoundArchives.size()))
        );
    }

    void exportSnapshots(bool bJson)
    {
        if (m_vecPackets.empty() && m_vecFailures.empty()
            && m_vecDosSummaries.empty())
        {
            QMessageBox::information(
                m_pOwner,
                QStringLiteral("导出"),
                QStringLiteral("当前没有可导出的本节点观测数据。")
            );
            return;
        }

        const QString strSuffix = bJson
            ? QStringLiteral("json")
            : QStringLiteral("csv");
        const QString strPath = QFileDialog::getSaveFileName(
            m_pOwner,
            QStringLiteral("导出本节点逐轮原始数据"),
            QStringLiteral("tesla-node-observations-%1.%2")
                .arg(
                    QDateTime::currentDateTime().toString(
                        QStringLiteral("yyyyMMdd-HHmmss")
                    ),
                    strSuffix
                ),
            bJson ? QStringLiteral("JSON (*.json)") : QStringLiteral("CSV (*.csv)")
        );
        if (strPath.isEmpty())
        {
            return;
        }

        QByteArray arrOutput;
        if (bJson)
        {
            QJsonArray arrPackets;
            for (const auto& detPacket : m_vecPackets)
            {
                QJsonObject objPacket;
                objPacket.insert(QStringLiteral("eventId"), QString::number(detPacket.u64EventId()));
                objPacket.insert(QStringLiteral("timestampMs"), QString::number(detPacket.u64TimestampMilliseconds()));
                objPacket.insert(QStringLiteral("roundId"), QString::fromStdString(detPacket.strRoundId()));
                objPacket.insert(QStringLiteral("senderId"), QString::fromStdString(detPacket.strSenderId()));
                objPacket.insert(QStringLiteral("senderIp"), QString::fromStdString(detPacket.strSenderIp()));
                objPacket.insert(QStringLiteral("actualSourceIp"), QString::fromStdString(detPacket.strActualSourceIp()));
                objPacket.insert(QStringLiteral("chainId"), QString::number(detPacket.u64ChainId()));
                objPacket.insert(QStringLiteral("intervalIndex"), static_cast<qint64>(detPacket.u32IntervalIndex()));
                objPacket.insert(QStringLiteral("packetIndex"), static_cast<qint64>(detPacket.u32PacketIndex()));
                objPacket.insert(QStringLiteral("authenticationStatus"), strPacketStatus(detPacket.statusAuthentication()));
                objPacket.insert(QStringLiteral("sourceType"), strSource(detPacket.typeSource()));
                objPacket.insert(QStringLiteral("duplicateCount"), static_cast<qint64>(detPacket.u32DuplicateCount()));
                objPacket.insert(QStringLiteral("reason"), QString::fromStdString(detPacket.strReason()));
                objPacket.insert(QStringLiteral("rawDatagramHex"), strHex(detPacket.vecRawDatagram()));
                arrPackets.append(objPacket);
            }

            QJsonArray arrFailures;
            for (const auto& detFailure : m_vecFailures)
            {
                QJsonArray arrLocated;
                for (const std::uint32_t u32Index : detFailure.vecLocatedPacketIndexes())
                {
                    arrLocated.append(static_cast<qint64>(u32Index));
                }
                QJsonObject objFailure;
                objFailure.insert(QStringLiteral("eventId"), QString::number(detFailure.u64EventId()));
                objFailure.insert(QStringLiteral("packetEventId"), QString::number(detFailure.u64PacketEventId()));
                objFailure.insert(QStringLiteral("timestampMs"), QString::number(detFailure.u64TimestampMilliseconds()));
                objFailure.insert(QStringLiteral("roundId"), QString::fromStdString(detFailure.strRoundId()));
                objFailure.insert(QStringLiteral("senderId"), QString::fromStdString(detFailure.strSenderId()));
                objFailure.insert(QStringLiteral("actualSourceIp"), QString::fromStdString(detFailure.strActualSourceIp()));
                objFailure.insert(QStringLiteral("chainId"), QString::number(detFailure.u64ChainId()));
                objFailure.insert(QStringLiteral("intervalIndex"), static_cast<qint64>(detFailure.u32IntervalIndex()));
                objFailure.insert(QStringLiteral("packetIndex"), static_cast<qint64>(detFailure.u32PacketIndex()));
                objFailure.insert(QStringLiteral("failureType"), strFailureType(detFailure.typeFailure()));
                objFailure.insert(QStringLiteral("duplicateCount"), static_cast<qint64>(detFailure.u32DuplicateCount()));
                objFailure.insert(QStringLiteral("reason"), QString::fromStdString(detFailure.strReason()));
                objFailure.insert(QStringLiteral("locatedPacketIndexes"), arrLocated);
                arrFailures.append(objFailure);
            }

            QJsonArray arrDosSummaries;
            for (const auto& detSummary : m_vecDosSummaries)
            {
                QJsonObject objSummary;
                objSummary.insert(QStringLiteral("timestampMs"), QString::number(detSummary.u64TimestampMilliseconds()));
                objSummary.insert(QStringLiteral("windowMs"), static_cast<qint64>(detSummary.u32WindowMilliseconds()));
                objSummary.insert(QStringLiteral("invalidPacketCount"), QString::number(detSummary.u64InvalidPacketCount()));
                objSummary.insert(QStringLiteral("rateLimitedDropCount"), QString::number(detSummary.u64RateLimitedDropCount()));
                objSummary.insert(QStringLiteral("legitimatePacketCount"), QString::number(detSummary.u64LegitimatePacketCount()));
                objSummary.insert(QStringLiteral("receiveQueueOverflowCount"), QString::number(detSummary.u64ReceiveQueueOverflowCount()));
                arrDosSummaries.append(objSummary);
            }

            QJsonObject objRoot;
            objRoot.insert(QStringLiteral("exportedAtMs"), QDateTime::currentMSecsSinceEpoch());
            objRoot.insert(QStringLiteral("packets"), arrPackets);
            objRoot.insert(QStringLiteral("failures"), arrFailures);
            objRoot.insert(QStringLiteral("dosSummaries"), arrDosSummaries);
            arrOutput = QJsonDocument(objRoot).toJson(QJsonDocument::Indented);
        }
        else
        {
            arrOutput.append("recordType,timestampMs,roundId,senderId,actualSourceIp,chainId,intervalIndex,packetIndex,statusOrType,duplicateCount,rawDatagramHex,details\r\n");
            for (const auto& detPacket : m_vecPackets)
            {
                const QString strLine = QStringLiteral("PACKET,%1,%2,%3,%4,%5,%6,%7,%8,%9,%10,%11\r\n")
                    .arg(detPacket.u64TimestampMilliseconds())
                    .arg(strCsv(QString::fromStdString(detPacket.strRoundId())))
                    .arg(strCsv(QString::fromStdString(detPacket.strSenderId())))
                    .arg(strCsv(QString::fromStdString(detPacket.strActualSourceIp())))
                    .arg(detPacket.u64ChainId())
                    .arg(detPacket.u32IntervalIndex())
                    .arg(detPacket.u32PacketIndex())
                    .arg(strCsv(strPacketStatus(detPacket.statusAuthentication())))
                    .arg(detPacket.u32DuplicateCount())
                    .arg(strCsv(strHex(detPacket.vecRawDatagram())))
                    .arg(strCsv(QString::fromStdString(detPacket.strReason())));
                arrOutput.append(strLine.toUtf8());
            }
            for (const auto& detFailure : m_vecFailures)
            {
                const QString strLine = QStringLiteral("FAILURE,%1,%2,%3,%4,%5,%6,%7,%8,%9,,%10\r\n")
                    .arg(detFailure.u64TimestampMilliseconds())
                    .arg(strCsv(QString::fromStdString(detFailure.strRoundId())))
                    .arg(strCsv(QString::fromStdString(detFailure.strSenderId())))
                    .arg(strCsv(QString::fromStdString(detFailure.strActualSourceIp())))
                    .arg(detFailure.u64ChainId())
                    .arg(detFailure.u32IntervalIndex())
                    .arg(detFailure.u32PacketIndex())
                    .arg(strCsv(strFailureType(detFailure.typeFailure())))
                    .arg(detFailure.u32DuplicateCount())
                    .arg(strCsv(QString::fromStdString(detFailure.strReason())));
                arrOutput.append(strLine.toUtf8());
            }
            for (const auto& detSummary : m_vecDosSummaries)
            {
                const QString strDetails = QStringLiteral(
                    "windowMs=%1; invalid=%2; limited=%3; legitimate=%4; overflow=%5"
                )
                    .arg(detSummary.u32WindowMilliseconds())
                    .arg(detSummary.u64InvalidPacketCount())
                    .arg(detSummary.u64RateLimitedDropCount())
                    .arg(detSummary.u64LegitimatePacketCount())
                    .arg(detSummary.u64ReceiveQueueOverflowCount());
                const QString strLine = QStringLiteral("DOS_SUMMARY,%1,,,,,,,DOS_SUMMARY,,,%2\r\n")
                    .arg(detSummary.u64TimestampMilliseconds())
                    .arg(strCsv(strDetails));
                arrOutput.append(strLine.toUtf8());
            }
        }

        QFile filOutput(strPath);
        if (!filOutput.open(QIODevice::WriteOnly | QIODevice::Truncate)
            || filOutput.write(arrOutput) != arrOutput.size())
        {
            QMessageBox::warning(
                m_pOwner,
                QStringLiteral("导出失败"),
                filOutput.errorString()
            );
            return;
        }

        QMessageBox::information(
            m_pOwner,
            QStringLiteral("导出完成"),
            QStringLiteral("本节点观测原始数据已导出。")
        );
    }

    void createPages()
    {
        QVBoxLayout* pRootLayout = new QVBoxLayout(m_pOwner);
        pRootLayout->addWidget(m_pTabs);

        QWidget* pPacketPage = new QWidget(m_pTabs);
        QVBoxLayout* pPacketLayout = new QVBoxLayout(pPacketPage);
        QHBoxLayout* pExportLayout = new QHBoxLayout();
        QPushButton* pExportCsvButton = new QPushButton(
            QStringLiteral("导出本节点CSV"),
            pPacketPage
        );
        QPushButton* pExportJsonButton = new QPushButton(
            QStringLiteral("导出本节点JSON"),
            pPacketPage
        );
        QPushButton* pExportRoundCsvButton = new QPushButton(
            QStringLiteral("导出逐轮CSV"),
            pPacketPage
        );
        QPushButton* pExportRoundJsonButton = new QPushButton(
            QStringLiteral("导出逐轮JSON"),
            pPacketPage
        );
        pExportLayout->addWidget(pExportCsvButton);
        pExportLayout->addWidget(pExportJsonButton);
        pExportLayout->addWidget(pExportRoundCsvButton);
        pExportLayout->addWidget(pExportRoundJsonButton);
        pExportLayout->addStretch();
        pPacketLayout->addLayout(pExportLayout);
        QGridLayout* pFilters = new QGridLayout();
        m_pQuickButtons = new QButtonGroup(m_pOwner);
        m_pQuickButtons->setExclusive(true);
        static const std::array<std::pair<const char*, QuickFilter>, 8> FILTERS{
            std::pair{"全部", QuickFilter::All},
            std::pair{"仅看异常", QuickFilter::Abnormal},
            std::pair{"MAC失败", QuickFilter::Mac},
            std::pair{"快速组失败", QuickFilter::FastGroup},
            std::pair{"τ失败", QuickFilter::Tau},
            std::pair{"重放", QuickFilter::Replay},
            std::pair{"协议错误", QuickFilter::Protocol},
            std::pair{"丢失", QuickFilter::Missing}
        };
        for (std::size_t nIndex = 0; nIndex < FILTERS.size(); ++nIndex)
        {
            QPushButton* pButton = new QPushButton(
                QString::fromUtf8(FILTERS[nIndex].first),
                pPacketPage
            );
            pButton->setCheckable(true);
            if (nIndex == 1U)
            {
                pButton->setObjectName(QStringLiteral("abnormalFilterButton"));
            }
            m_pQuickButtons->addButton(pButton, static_cast<int>(nIndex));
            m_vecQuickButtons.push_back(pButton);
            pFilters->addWidget(pButton, 0, static_cast<int>(nIndex));
        }
        m_vecQuickButtons.front()->setChecked(true);

        pFilters->addWidget(new QLabel(QStringLiteral("Sender"), pPacketPage), 1, 0);
        pFilters->addWidget(m_pSenderEdit, 1, 1);
        pFilters->addWidget(new QLabel(QStringLiteral("Chain ID"), pPacketPage), 1, 2);
        pFilters->addWidget(m_pChainEdit, 1, 3);
        pFilters->addWidget(new QLabel(QStringLiteral("报文编号"), pPacketPage), 1, 4);
        pFilters->addWidget(m_pPacketEdit, 1, 5);
        pFilters->addWidget(new QLabel(QStringLiteral("间隔编号"), pPacketPage), 1, 6);
        pFilters->addWidget(m_pIntervalEdit, 1, 7);
        pFilters->addWidget(new QLabel(QStringLiteral("实际源IP"), pPacketPage), 2, 0);
        pFilters->addWidget(m_pSourceEdit, 2, 1, 1, 2);
        pFilters->addWidget(new QLabel(QStringLiteral("结果状态"), pPacketPage), 2, 3);
        pFilters->addWidget(m_pStatusCombo, 2, 4);
        QPushButton* pQueryButton = new QPushButton(QStringLiteral("查询"), pPacketPage);
        QPushButton* pClearButton = new QPushButton(QStringLiteral("清除筛选"), pPacketPage);
        pFilters->addWidget(pQueryButton, 2, 6);
        pFilters->addWidget(pClearButton, 2, 7);
        pPacketLayout->addLayout(pFilters);
        pPacketLayout->addWidget(m_pDosLabel);

        QSplitter* pSplitter = new QSplitter(Qt::Vertical, pPacketPage);
        pSplitter->addWidget(m_pPacketTable);
        pSplitter->addWidget(m_pDetailEdit);
        pSplitter->setStretchFactor(0, 3);
        pSplitter->setStretchFactor(1, 2);
        pPacketLayout->addWidget(pSplitter, 1);
        m_pTabs->addTab(pPacketPage, QStringLiteral("报文列表与详情"));

        QWidget* pFailurePage = new QWidget(m_pTabs);
        QVBoxLayout* pFailureLayout = new QVBoxLayout(pFailurePage);
        QLabel* pHint = new QLabel(
            QStringLiteral("双击异常可定位对应候选报文；缺失报文打开预期槽位详情。"),
            pFailurePage
        );
        pFailureLayout->addWidget(pHint);
        pFailureLayout->addWidget(m_pFailureTable, 1);
        m_pTabs->addTab(pFailurePage, QStringLiteral("异常记录"));

        QWidget* pLogPage = new QWidget(m_pTabs);
        QVBoxLayout* pLogLayout = new QVBoxLayout(pLogPage);
        pLogLayout->addWidget(new QLabel(
            QStringLiteral(
                "结构化失败日志只显示摘要；完整Message、认证字段和原始字节请双击查看。"
            ),
            pLogPage
        ));
        pLogLayout->addWidget(m_pLogTable, 1);
        m_pTabs->addTab(pLogPage, QStringLiteral("结构化日志"));

        m_pPacketTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_pPacketTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_pPacketTable->setSortingEnabled(true);
        m_pPacketTable->horizontalHeader()->setStretchLastSection(true);
        m_pFailureTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_pFailureTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_pFailureTable->horizontalHeader()->setStretchLastSection(true);
        m_pLogTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_pLogTable->setSelectionMode(QAbstractItemView::SingleSelection);
        m_pLogTable->horizontalHeader()->setStretchLastSection(true);

        QObject::connect(pQueryButton, &QPushButton::clicked, m_pOwner, [this]()
        {
            applyQuery();
        });
        QObject::connect(pClearButton, &QPushButton::clicked, m_pOwner, [this]()
        {
            clearFilters();
        });
        QObject::connect(
            pExportCsvButton,
            &QPushButton::clicked,
            m_pOwner,
            [this]()
            {
                exportSnapshots(false);
            }
        );
        QObject::connect(
            pExportJsonButton,
            &QPushButton::clicked,
            m_pOwner,
            [this]()
            {
                exportSnapshots(true);
            }
        );
        QObject::connect(
            pExportRoundCsvButton,
            &QPushButton::clicked,
            m_pOwner,
            [this]()
            {
                exportRoundArchives(false);
            }
        );
        QObject::connect(
            pExportRoundJsonButton,
            &QPushButton::clicked,
            m_pOwner,
            [this]()
            {
                exportRoundArchives(true);
            }
        );
    }

    void connectActions()
    {
        QObject::connect(
            m_pQuickButtons,
            &QButtonGroup::idClicked,
            m_pOwner,
            [this](int nId)
            {
                m_pProxyModel->setQuickFilter(
                    static_cast<QuickFilter>(nId)
                );
            }
        );
        QObject::connect(
            m_pPacketTable->selectionModel(),
            &QItemSelectionModel::currentRowChanged,
            m_pOwner,
            [this](const QModelIndex& idxCurrent)
            {
                const QModelIndex idxSource = m_pProxyModel->mapToSource(
                    idxCurrent
                );
                const auto* pPacket = m_pPacketModel->pPacket(idxSource.row());
                m_pDetailEdit->setPlainText(
                    pPacket == nullptr ? QString() : strPacketDetails(*pPacket)
                );
            }
        );
        QObject::connect(
            m_pFailureTable,
            &QTableView::doubleClicked,
            m_pOwner,
            [this](const QModelIndex& idxFailure)
            {
                jumpToFailure(idxFailure.row());
            }
        );
        QObject::connect(
            m_pLogTable,
            &QTableView::doubleClicked,
            m_pOwner,
            [this](const QModelIndex& idxFailure)
            {
                jumpToFailure(idxFailure.row());
            }
        );
    }

    void applyQuery()
    {
        m_pProxyModel->setQuery(
            m_pSenderEdit->text(),
            m_pChainEdit->text(),
            m_pPacketEdit->text(),
            m_pIntervalEdit->text(),
            m_pSourceEdit->text(),
            m_pStatusCombo->currentText()
        );
        refreshQuickButtonCounts();
    }

    void clearFilters()
    {
        for (QLineEdit* pEdit : {
                m_pSenderEdit,
                m_pChainEdit,
                m_pPacketEdit,
                m_pIntervalEdit,
                m_pSourceEdit
            })
        {
            pEdit->clear();
        }
        m_pStatusCombo->setCurrentIndex(0);
        m_vecQuickButtons.front()->setChecked(true);
        m_pProxyModel->setQuickFilter(QuickFilter::All);
        applyQuery();
    }

    void jumpToFailure(int nFailureRow)
    {
        const auto* pFailure = m_pFailureModel->pFailure(nFailureRow);
        if (pFailure == nullptr)
        {
            return;
        }
        clearFilters();
        m_pTabs->setCurrentIndex(0);
        if (pFailure->u64PacketEventId() == 0)
        {
            m_pPacketTable->clearSelection();
            m_pDetailEdit->setPlainText(strFailureDetails(*pFailure));
            return;
        }

        const int nSourceRow = m_pPacketModel->nRowForEventId(
            pFailure->u64PacketEventId()
        );
        const QModelIndex idxProxy = m_pProxyModel->mapFromSource(
            m_pPacketModel->index(nSourceRow, 0)
        );
        if (idxProxy.isValid())
        {
            m_pPacketTable->selectRow(idxProxy.row());
            m_pPacketTable->scrollTo(idxProxy);
            const auto* pPacket = m_pPacketModel->pPacket(nSourceRow);
            m_pDetailEdit->setPlainText(
                strPacketDetails(*pPacket)
                + QStringLiteral("\n\n--- 关联异常 ---\n")
                + strFailureDetails(*pFailure)
            );
        }
        else
        {
            m_pDetailEdit->setPlainText(strFailureDetails(*pFailure));
        }
    }

    void refreshQuickButtonCounts()
    {
        std::array<int, 8> arrCounts{};
        arrCounts[0] = m_pPacketModel->rowCount();
        for (const auto& detFailure : m_pFailureModel->vecFailures())
        {
            if ((!m_pSenderEdit->text().trimmed().isEmpty()
                    && QString::fromStdString(detFailure.strSenderId())
                        != m_pSenderEdit->text().trimmed())
                || (!m_pChainEdit->text().trimmed().isEmpty()
                    && QString::number(detFailure.u64ChainId())
                        != m_pChainEdit->text().trimmed())
                || (!m_pPacketEdit->text().trimmed().isEmpty()
                    && QString::number(detFailure.u32PacketIndex())
                        != m_pPacketEdit->text().trimmed())
                || (!m_pIntervalEdit->text().trimmed().isEmpty()
                    && QString::number(detFailure.u32IntervalIndex())
                        != m_pIntervalEdit->text().trimmed())
                || (!m_pSourceEdit->text().trimmed().isEmpty()
                    && !QString::fromStdString(
                        detFailure.strActualSourceIp()
                    ).contains(
                        m_pSourceEdit->text().trimmed(),
                        Qt::CaseInsensitive
                    )))
            {
                continue;
            }

            ++arrCounts[1];
            const auto typeFailure = detFailure.typeFailure();
            if (typeFailure == AuthenticationFailureType::MacFailed
                || typeFailure == AuthenticationFailureType::TamperedVariant)
            {
                ++arrCounts[2];
            }
            else if (typeFailure == AuthenticationFailureType::FastGroupFailed)
            {
                ++arrCounts[3];
            }
            else if (typeFailure == AuthenticationFailureType::GroupTauFailed)
            {
                ++arrCounts[4];
            }
            else if (bIsReplay(typeFailure))
            {
                ++arrCounts[5];
            }
            else if (typeFailure == AuthenticationFailureType::ProtocolError
                || typeFailure == AuthenticationFailureType::UnknownContext)
            {
                ++arrCounts[6];
            }
            else if (typeFailure == AuthenticationFailureType::MissingPacket
                || typeFailure == AuthenticationFailureType::IncompleteGroupTags
                || typeFailure
                    == AuthenticationFailureType::UnverifiableMissingBaseline)
            {
                ++arrCounts[7];
            }
        }
        static const std::array<const char*, 8> NAMES{
            "全部", "仅看异常", "MAC失败", "快速组失败", "τ失败", "重放",
            "协议错误", "丢失"
        };
        for (std::size_t nIndex = 0; nIndex < m_vecQuickButtons.size(); ++nIndex)
        {
            m_vecQuickButtons[nIndex]->setText(
                QStringLiteral("%1(%2)")
                    .arg(QString::fromUtf8(NAMES[nIndex]))
                    .arg(arrCounts[nIndex])
            );
        }
    }

    AuthenticationMonitorWidget* m_pOwner;
    PacketTableModel*             m_pPacketModel;
    FailureTableModel*            m_pFailureModel;
    PacketFilterProxyModel*       m_pProxyModel;
    QTabWidget*                   m_pTabs;
    QTableView*                   m_pPacketTable;
    QTableView*                   m_pFailureTable;
    QTableView*                   m_pLogTable;
    QTextEdit*                    m_pDetailEdit;
    QLineEdit*                    m_pSenderEdit;
    QLineEdit*                    m_pChainEdit;
    QLineEdit*                    m_pPacketEdit;
    QLineEdit*                    m_pIntervalEdit;
    QLineEdit*                    m_pSourceEdit;
    QComboBox*                    m_pStatusCombo;
    QLabel*                       m_pDosLabel;
    QButtonGroup*                 m_pQuickButtons{nullptr};
    std::vector<QPushButton*>     m_vecQuickButtons;
    std::vector<PacketObservationControlDetails> m_vecPackets;
    std::vector<PacketFailureControlDetails> m_vecFailures;
    std::vector<DosSummaryControlDetails> m_vecDosSummaries;
    std::vector<AuthenticationRoundArchiveSummary> m_vecRoundArchives;
};

AuthenticationMonitorWidget::AuthenticationMonitorWidget(QWidget* pParent)
    : QWidget(pParent),
      m_pImpl(new Impl(this))
{
}

AuthenticationMonitorWidget::~AuthenticationMonitorWidget()
{
    delete m_pImpl;
}

void AuthenticationMonitorWidget::setSnapshots(
    std::vector<PacketObservationControlDetails> vecPackets,
    std::vector<PacketFailureControlDetails> vecFailures,
    std::vector<DosSummaryControlDetails> vecDosSummaries
)
{
    m_pImpl->setSnapshots(
        std::move(vecPackets),
        std::move(vecFailures),
        std::move(vecDosSummaries)
    );
}

void AuthenticationMonitorWidget::setMetricSnapshots(
    std::vector<metrics::AuthenticationMetricRecord> vecMetrics
)
{
    m_pImpl->setMetricSnapshots(std::move(vecMetrics));
}
}
