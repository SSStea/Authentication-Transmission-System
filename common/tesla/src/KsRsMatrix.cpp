#include "tesla/core/KsRsMatrix.h"

#include <limits>
#include <stdexcept>

namespace tesla::core
{
namespace
{
constexpr std::size_t MAX_FIELD_SIZE = 10000;
constexpr std::size_t MAX_MESSAGE_LENGTH = 64;
}

KsRsMatrix::KsRsMatrix(std::size_t nGroupSize, std::size_t nDetectionThreshold)
    : m_nGroupSize(nGroupSize),
      m_nDetectionThreshold(nDetectionThreshold)
{
    if (m_nGroupSize == 0)
    {
        throw std::invalid_argument("KS+RS group size must be positive");
    }

    if (m_nDetectionThreshold == 0 || m_nDetectionThreshold >= m_nGroupSize)
    {
        throw std::invalid_argument("KS+RS detection threshold must be within the group size");
    }

    buildMatrix();
}

bool KsRsMatrix::bRowContains(std::size_t nRowIndex, std::size_t nColumnIndex) const
{
    if (nRowIndex >= m_vecRows.size() || nColumnIndex >= m_nGroupSize)
    {
        throw std::out_of_range("KS+RS matrix index is out of range");
    }

    return m_vecRows[nRowIndex][nColumnIndex];
}

std::size_t KsRsMatrix::nDetectionThreshold() const noexcept
{
    return m_nDetectionThreshold;
}

std::size_t KsRsMatrix::nGroupSize() const noexcept
{
    return m_nGroupSize;
}

std::size_t KsRsMatrix::nRowCount() const noexcept
{
    return m_vecRows.size();
}

bool KsRsMatrix::bIsPrime(std::size_t nValue)
{
    if (nValue <= 1)
    {
        return false;
    }

    if (nValue == 2 || nValue == 3)
    {
        return true;
    }

    if ((nValue & 1U) == 0)
    {
        return false;
    }

    for (std::size_t nDivisor = 3; nDivisor <= nValue / nDivisor; nDivisor += 2)
    {
        if (nValue % nDivisor == 0)
        {
            return false;
        }
    }

    return true;
}

std::size_t KsRsMatrix::nMinExponent(std::size_t nGroupSize, std::size_t nFieldSize)
{
    std::size_t nExponent = 0;
    std::size_t nCapacity = 1;

    while (nCapacity < nGroupSize && nExponent < MAX_MESSAGE_LENGTH)
    {
        if (nCapacity > std::numeric_limits<std::size_t>::max() / nFieldSize)
        {
            return 0;
        }

        nCapacity *= nFieldSize;
        ++nExponent;
    }

    return nCapacity >= nGroupSize && nExponent > 0 ? nExponent : 0;
}

std::size_t KsRsMatrix::nNextPrime(std::size_t nValue)
{
    if (nValue <= 2)
    {
        return 2;
    }

    std::size_t nCandidate = (nValue & 1U) == 0 ? nValue + 1 : nValue;

    while (!bIsPrime(nCandidate))
    {
        nCandidate += 2;
    }

    return nCandidate;
}

std::size_t KsRsMatrix::nPowMod(
    std::size_t nBase,
    std::size_t nExponent,
    std::size_t nModulus
)
{
    std::size_t nResult = 1;
    std::size_t nFactor = nBase % nModulus;
    std::size_t nRemainingExponent = nExponent;

    while (nRemainingExponent > 0)
    {
        if ((nRemainingExponent & 1U) != 0)
        {
            nResult = (nResult * nFactor) % nModulus;
        }

        nFactor = (nFactor * nFactor) % nModulus;
        nRemainingExponent >>= 1U;
    }

    return nResult;
}

void KsRsMatrix::buildMatrix()
{
    std::size_t nFieldSize = 0;
    std::size_t nCodeLength = 0;
    std::size_t nMessageLength = 0;
    std::size_t nRowCount = 0;
    findBestParameters(nFieldSize, nCodeLength, nMessageLength, nRowCount);

    m_vecRows.assign(nRowCount, std::vector<bool>(m_nGroupSize, false));

    // 每个报文位置编码为有限域上的消息多项式系数。
    for (std::size_t nColumnIndex = 0; nColumnIndex < m_nGroupSize; ++nColumnIndex)
    {
        std::size_t              nRemainingValue = nColumnIndex;
        std::vector<std::size_t> vecCoefficients(nMessageLength, 0);

        for (std::size_t nCoefficientIndex = 0;
             nCoefficientIndex < nMessageLength;
             ++nCoefficientIndex)
        {
            vecCoefficients[nCoefficientIndex] = nRemainingValue % nFieldSize;
            nRemainingValue /= nFieldSize;
        }

        // 在不同域元素上求值，所得“求值点+符号”共同选择一条矩阵行。
        for (std::size_t nEvaluationIndex = 0;
             nEvaluationIndex < nCodeLength;
             ++nEvaluationIndex)
        {
            std::size_t nSymbol = 0;

            for (std::size_t nCoefficientIndex = 0;
                 nCoefficientIndex < nMessageLength;
                 ++nCoefficientIndex)
            {
                nSymbol += vecCoefficients[nCoefficientIndex]
                    * nPowMod(nEvaluationIndex, nCoefficientIndex, nFieldSize);
                nSymbol %= nFieldSize;
            }

            const std::size_t nRowIndex = nEvaluationIndex * nFieldSize + nSymbol;
            m_vecRows[nRowIndex][nColumnIndex] = true;
        }
    }
}

void KsRsMatrix::findBestParameters(
    std::size_t& nFieldSize,
    std::size_t& nCodeLength,
    std::size_t& nMessageLength,
    std::size_t& nRowCount
) const
{
    // 域大小至少覆盖2t+1；在可行候选中选择总行数最少的矩阵。
    std::size_t nCandidateFieldSize = nNextPrime(2 * m_nDetectionThreshold + 1);
    std::size_t nBestRowCount = std::numeric_limits<std::size_t>::max();

    while (nCandidateFieldSize <= MAX_FIELD_SIZE)
    {
        const std::size_t nCandidateMessageLength = nMinExponent(
            m_nGroupSize,
            nCandidateFieldSize
        );

        if (nCandidateMessageLength > 0)
        {
            const std::size_t nCandidateCodeLength = nCandidateMessageLength
                + 2 * m_nDetectionThreshold;

            if (nCandidateCodeLength <= nCandidateFieldSize)
            {
                const std::size_t nCandidateRowCount = nCandidateCodeLength
                    * nCandidateFieldSize;

                if (nCandidateRowCount < nBestRowCount)
                {
                    nFieldSize = nCandidateFieldSize;
                    nCodeLength = nCandidateCodeLength;
                    nMessageLength = nCandidateMessageLength;
                    nRowCount = nCandidateRowCount;
                    nBestRowCount = nCandidateRowCount;
                }
            }
        }

        nCandidateFieldSize = nNextPrime(nCandidateFieldSize + 1);
    }

    if (nBestRowCount == std::numeric_limits<std::size_t>::max())
    {
        throw std::runtime_error("No valid KS+RS matrix parameters were found");
    }
}
}
