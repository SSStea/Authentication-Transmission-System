#include "PcAuthenticationViews.h"

#include <QColor>
#include <QAbstractItemView>
#include <QComboBox>
#include <QHeaderView>
#include <QLabel>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QStringList>

#include <algorithm>
#include <array>
#include <cstdint>

namespace
{
QString strHex(const tesla::crypto::Digest& arrDigest)
{
    static constexpr char HEX[] = "0123456789abcdef";
    QString strValue;
    strValue.reserve(static_cast<qsizetype>(arrDigest.size() * 2U));
    for (const std::uint8_t u8Value : arrDigest)
    {
        strValue.append(QLatin1Char(HEX[(u8Value >> 4U) & 0x0FU]));
        strValue.append(QLatin1Char(HEX[u8Value & 0x0FU]));
    }
    return strValue;
}

QString strIndexes(const std::vector<std::uint32_t>& vecIndexes)
{
    if (vecIndexes.empty())
    {
        return QStringLiteral("无");
    }
    QStringList lstIndexes;
    for (const std::uint32_t u32Index : vecIndexes)
    {
        lstIndexes << QString::number(u32Index);
    }
    return lstIndexes.join(QStringLiteral(", "));
}
}

PcLocalKeyChainWidget::PcLocalKeyChainWidget(QWidget* pParent)
    : QWidget(pParent),
      m_pSummaryLabel(new QLabel(this)),
      m_pKeyTable(new QTableWidget(this))
{
    QVBoxLayout* pLayout = new QVBoxLayout(this);
    m_pSummaryLabel->setWordWrap(true);
    m_pKeyTable->setColumnCount(4);
    m_pKeyTable->setHorizontalHeaderLabels({
        QStringLiteral("密钥编号"),
        QStringLiteral("完整密钥值"),
        QStringLiteral("使用状态"),
        QStringLiteral("披露状态")
    });
    m_pKeyTable->horizontalHeader()->setSectionResizeMode(
        1,
        QHeaderView::Stretch
    );
    m_pKeyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    pLayout->addWidget(m_pSummaryLabel);
    pLayout->addWidget(m_pKeyTable, 1);
    setKeyChain(std::nullopt, std::nullopt);
}

void PcLocalKeyChainWidget::setKeyChain(
    std::optional<tesla::core::LocalSenderKeyChainSnapshot> optSnapshot,
    std::optional<tesla::core::LocalSenderKeyChainProgress> optProgress
)
{
    m_pKeyTable->setRowCount(0);
    if (!optSnapshot.has_value())
    {
        m_pSummaryLabel->setText(
            QStringLiteral("本轮PC节点未启用Sender，无本地密钥链。")
        );
        return;
    }

    const auto& detSnapshot = optSnapshot.value();
    m_pSummaryLabel->setText(QStringLiteral(
        "本地Sender=%1，Chain ID=%2，披露延迟=%3，密钥数量=%4。"
    )
        .arg(QString::fromStdString(detSnapshot.strSenderId()))
        .arg(detSnapshot.u64ChainId())
        .arg(detSnapshot.u32DisclosureDelay())
        .arg(static_cast<qulonglong>(detSnapshot.vecKeys().size())));
    m_pKeyTable->setRowCount(
        static_cast<int>(detSnapshot.vecKeys().size())
    );

    for (std::size_t nIndex = 0; nIndex < detSnapshot.vecKeys().size(); ++nIndex)
    {
        QString strUseStatus = QStringLiteral("等待");
        QString strDisclosureStatus = QStringLiteral("未披露");
        QColor clrRow(235, 235, 235);
        if (nIndex == 0U)
        {
            strUseStatus = QStringLiteral("承诺值");
            strDisclosureStatus = QStringLiteral("不披露");
            clrRow = QColor(210, 228, 255);
        }
        else if (optProgress.has_value())
        {
            const auto& detProgress = optProgress.value();
            if (detProgress.bCompleted()
                || nIndex <= detProgress.u32DisclosedThroughKeyIndex())
            {
                strUseStatus = QStringLiteral("已使用");
                strDisclosureStatus = QStringLiteral("已披露");
                clrRow = QColor(210, 245, 218);
            }
            else if (nIndex == detProgress.u32CurrentDataKeyIndex())
            {
                strUseStatus = QStringLiteral("当前");
                strDisclosureStatus = QStringLiteral("等待披露");
                clrRow = QColor(255, 244, 176);
            }
            else if (nIndex < detProgress.u32CurrentDataKeyIndex())
            {
                strUseStatus = QStringLiteral("已使用");
                strDisclosureStatus = QStringLiteral("等待披露");
                clrRow = QColor(255, 225, 185);
            }
        }

        const std::array<QString, 4> arrValues{
            QStringLiteral("K%1").arg(nIndex),
            strHex(detSnapshot.vecKeys()[nIndex]),
            strUseStatus,
            strDisclosureStatus
        };
        for (int nColumn = 0; nColumn < 4; ++nColumn)
        {
            auto* pItem = new QTableWidgetItem(
                arrValues[static_cast<std::size_t>(nColumn)]
            );
            pItem->setBackground(clrRow);
            m_pKeyTable->setItem(static_cast<int>(nIndex), nColumn, pItem);
        }
    }
}

PcMatrixLocationWidget::PcMatrixLocationWidget(QWidget* pParent)
    : QWidget(pParent),
      m_pGroupCombo(new QComboBox(this)),
      m_pSummaryLabel(new QLabel(this)),
      m_pStepTable(new QTableWidget(this))
{
    QVBoxLayout* pLayout = new QVBoxLayout(this);
    pLayout->addWidget(new QLabel(QStringLiteral("认证分组"), this));
    pLayout->addWidget(m_pGroupCombo);
    m_pSummaryLabel->setWordWrap(true);
    pLayout->addWidget(m_pSummaryLabel);
    m_pStepTable->setColumnCount(4);
    m_pStepTable->setHorizontalHeaderLabels({
        QStringLiteral("步骤"),
        QStringLiteral("操作"),
        QStringLiteral("新排除的好包"),
        QStringLiteral("剩余坏包候选")
    });
    m_pStepTable->horizontalHeader()->setStretchLastSection(true);
    m_pStepTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    pLayout->addWidget(m_pStepTable, 1);

    connect(
        m_pGroupCombo,
        &QComboBox::currentIndexChanged,
        this,
        [this](int)
        {
            refreshSelectedGroup();
        }
    );
    refreshSelectedGroup();
}

void PcMatrixLocationWidget::setGroups(
    std::vector<tesla::protocol::ImprovedGroupObservationControlDetails>
        vecGroups
)
{
    const int nPreviousIndex = m_pGroupCombo->currentIndex();
    m_vecGroups = std::move(vecGroups);
    m_pGroupCombo->blockSignals(true);
    m_pGroupCombo->clear();
    for (const auto& detGroup : m_vecGroups)
    {
        m_pGroupCombo->addItem(QStringLiteral(
            "Sender=%1 / Chain=%2 / Group=%3 / Packets=%4-%5"
        )
            .arg(QString::fromStdString(detGroup.strSenderId()))
            .arg(detGroup.u64ChainId())
            .arg(detGroup.u32GroupIndex())
            .arg(detGroup.u32FirstPacketIndex())
            .arg(detGroup.u32LastPacketIndex()));
    }
    if (!m_vecGroups.empty())
    {
        m_pGroupCombo->setCurrentIndex(std::clamp(
            nPreviousIndex,
            0,
            static_cast<int>(m_vecGroups.size()) - 1
        ));
    }
    m_pGroupCombo->blockSignals(false);
    refreshSelectedGroup();
}

void PcMatrixLocationWidget::refreshSelectedGroup()
{
    const int nIndex = m_pGroupCombo->currentIndex();
    m_pStepTable->setRowCount(0);
    if (nIndex < 0 || nIndex >= static_cast<int>(m_vecGroups.size()))
    {
        m_pSummaryLabel->setText(
            QStringLiteral("暂无改进TESLA分组验证记录。")
        );
        return;
    }

    const auto& detGroup = m_vecGroups[static_cast<std::size_t>(nIndex)];
    if (detGroup.pathVerification()
        == tesla::protocol::GroupVerificationPath::FastGroupPass)
    {
        m_pSummaryLabel->setText(
            QStringLiteral("本组认证通过，无坏包，不进入矩阵定位。")
        );
        return;
    }

    m_pSummaryLabel->setText(QStringLiteral(
        "分组=%1，分组大小=%2，检测阈值=%3，坏包数量=%4，"
        "全局坏包编号=%5，超过阈值=%6。"
    )
        .arg(detGroup.u32GroupIndex())
        .arg(detGroup.u32LastPacketIndex()
            - detGroup.u32FirstPacketIndex() + 1U)
        .arg(detGroup.u32DetectionThreshold())
        .arg(static_cast<qulonglong>(
            detGroup.vecLocatedPacketIndexes().size()
        ))
        .arg(strIndexes(detGroup.vecLocatedPacketIndexes()))
        .arg(detGroup.bDetectionThresholdExceeded()
            ? QStringLiteral("是") : QStringLiteral("否")));

    m_pStepTable->setRowCount(
        static_cast<int>(detGroup.vecLocationSteps().size())
    );
    for (std::size_t nStep = 0;
         nStep < detGroup.vecLocationSteps().size();
         ++nStep)
    {
        const auto& detStep = detGroup.vecLocationSteps()[nStep];
        const std::array<QString, 4> arrValues{
            QString::number(detStep.u32StepIndex()),
            QString::fromStdString(detStep.strOperation()),
            strIndexes(detStep.vecNewGoodPacketIndexes()),
            strIndexes(detStep.vecRemainingCandidateIndexes())
        };
        for (int nColumn = 0; nColumn < 4; ++nColumn)
        {
            m_pStepTable->setItem(
                static_cast<int>(nStep),
                nColumn,
                new QTableWidgetItem(
                    arrValues[static_cast<std::size_t>(nColumn)]
                )
            );
        }
    }
}
