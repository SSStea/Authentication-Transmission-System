#pragma once

#include "tesla/core/LocalSenderKeyChainObservation.h"
#include "tesla/protocol/MonitorControl.h"

#include <QWidget>

#include <optional>
#include <vector>

class QLabel;
class QComboBox;
class QTableWidget;

/** @brief 仅展示PC本地Sender私有密钥链，不接受任何远程密钥数据。 */
class PcLocalKeyChainWidget final : public QWidget
{
public:
    explicit PcLocalKeyChainWidget(QWidget* pParent = nullptr);

    void setKeyChain(
        std::optional<tesla::core::LocalSenderKeyChainSnapshot> optSnapshot,
        std::optional<tesla::core::LocalSenderKeyChainProgress> optProgress
    );

private:
    QLabel*       m_pSummaryLabel;
    QTableWidget* m_pKeyTable;
};

/** @brief 展示PC作为Receiver时改进TESLA的实际KS+RS定位步骤。 */
class PcMatrixLocationWidget final : public QWidget
{
public:
    explicit PcMatrixLocationWidget(QWidget* pParent = nullptr);

    void setGroups(
        std::vector<tesla::protocol::ImprovedGroupObservationControlDetails>
            vecGroups
    );

private:
    void refreshSelectedGroup();

    std::vector<tesla::protocol::ImprovedGroupObservationControlDetails>
        m_vecGroups;
    QComboBox*    m_pGroupCombo;
    QLabel*       m_pSummaryLabel;
    QTableWidget* m_pStepTable;
};
