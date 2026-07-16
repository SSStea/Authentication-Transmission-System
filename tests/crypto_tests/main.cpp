#include "tesla/crypto/CryptoProvider.h"
#include "tesla/crypto/CryptoUtilities.h"
#include "tesla/crypto/KeyChain.h"
#include "tesla/crypto/OpenSslCryptoProvider.h"
#include "tesla/crypto/OpenSslSecureRandomProvider.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
using tesla::crypto::ByteBuffer;
using tesla::crypto::CryptoAlgorithm;
using tesla::crypto::CryptoProvider;
using tesla::crypto::CryptoUtilities;
using tesla::crypto::Digest;
using tesla::crypto::KeyChain;
using tesla::crypto::KeyChainVerifier;
using tesla::crypto::OpenSslCryptoProvider;
using tesla::crypto::OpenSslSecureRandomProvider;

// 测试辅助：把可读字符串转换为密码接口使用的原始字节。
ByteBuffer vecFromString(const std::string& strValue)
{
    return ByteBuffer(strValue.begin(), strValue.end());
}

// 测试辅助：把二进制摘要转换为小写十六进制，以便比对标准向量。
std::string strDigestToHex(const Digest& digValue)
{
    static constexpr std::array<char, 16> arrHex = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    std::string strResult;
    strResult.reserve(digValue.size() * 2);

    for (std::uint8_t u8Value : digValue)
    {
        strResult.push_back(arrHex[(u8Value >> 4) & 0x0F]);
        strResult.push_back(arrHex[u8Value & 0x0F]);
    }

    return strResult;
}

// 统一记录断言失败，同时允许一个测试进程继续报告后续失败项。
bool bExpect(bool bCondition, const std::string& strDescription)
{
    if (!bCondition)
    {
        std::cerr << "FAILED: " << strDescription << std::endl;
        return false;
    }

    return true;
}

// 使用公开标准向量验证每种算法的摘要和HMAC实现。
bool bTestProviderVectors(
    CryptoAlgorithm algAlgorithm,
    const std::string& strExpectedHash,
    const std::string& strExpectedHmac
)
{
    const OpenSslCryptoProvider crpProvider(algAlgorithm);
    const ByteBuffer            vecHashInput = vecFromString("abc");
    const ByteBuffer            vecHmacKey = vecFromString("key");
    const ByteBuffer            vecHmacInput = vecFromString(
        "The quick brown fox jumps over the lazy dog"
    );
    const Digest                digHash = crpProvider.digHash(vecHashInput);
    const Digest                digHmac = crpProvider.digHmac(vecHmacKey, vecHmacInput);

    return bExpect(strDigestToHex(digHash) == strExpectedHash, "Hash test vector")
        && bExpect(strDigestToHex(digHmac) == strExpectedHmac, "HMAC test vector");
}

// 验证密钥链索引、合法披露密钥和篡改披露密钥拒绝行为。
bool bTestKeyChain(CryptoAlgorithm algAlgorithm)
{
    const OpenSslCryptoProvider crpProvider(algAlgorithm);
    const KeyChain              keyChain = KeyChain::keyCreate(
        crpProvider,
        vecFromString("stage2-key-chain-seed"),
        3
    );

    bool bResult = bExpect(keyChain.nDataIntervalCount() == 3, "Key-chain interval count");

    for (std::size_t nIntervalIndex = 1; nIntervalIndex <= 3; ++nIntervalIndex)
    {
        bResult = bExpect(
            KeyChainVerifier::bVerifyDisclosedKey(
                crpProvider,
                keyChain.digDataKey(nIntervalIndex),
                nIntervalIndex,
                keyChain.digCommitmentKey()
            ),
            "Disclosed key verification"
        ) && bResult;
    }

    Digest digTamperedKey = keyChain.digDataKey(2);
    digTamperedKey[0] ^= 0x01;
    bResult = bExpect(
        !KeyChainVerifier::bVerifyDisclosedKey(
            crpProvider,
            digTamperedKey,
            2,
            keyChain.digCommitmentKey()
        ),
        "Tampered disclosed key rejection"
    ) && bResult;

    return bResult;
}

// 验证正式随机源返回指定长度且拒绝无意义的零长度请求。
bool bTestSecureRandomProvider()
{
    const OpenSslSecureRandomProvider rngProvider;
    const ByteBuffer vecFirst = rngProvider.vecGenerateBytes(32);
    const ByteBuffer vecSecond = rngProvider.vecGenerateBytes(32);
    bool bRejectedZeroLength = false;

    try
    {
        static_cast<void>(rngProvider.vecGenerateBytes(0));
    }
    catch (const std::invalid_argument&)
    {
        bRejectedZeroLength = true;
    }

    return bExpect(vecFirst.size() == 32 && vecSecond.size() == 32, "Secure random length")
        && bExpect(vecFirst != vecSecond, "Independent secure random outputs")
        && bExpect(bRejectedZeroLength, "Zero-length secure random request is rejected");
}
}

int main()
{
    bool bPassed = true;

    bPassed = bTestProviderVectors(
        CryptoAlgorithm::Sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    ) && bPassed;
    bPassed = bTestProviderVectors(
        CryptoAlgorithm::Sm3,
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        "bd4a34077888162b210645b8ebf74b9af357303789357a27c7fc457244ebd398"
    ) && bPassed;
    bPassed = bTestProviderVectors(
        CryptoAlgorithm::Sha3_256,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "8c6e0683409427f8931711b10ca92a506eb1fafa48fadd66d76126f47ac2c333"
    ) && bPassed;

    for (CryptoAlgorithm algAlgorithm : {
             CryptoAlgorithm::Sha256,
             CryptoAlgorithm::Sm3,
             CryptoAlgorithm::Sha3_256
         })
    {
        bPassed = bTestKeyChain(algAlgorithm) && bPassed;
    }

    bPassed = bTestSecureRandomProvider() && bPassed;

    if (!bPassed)
    {
        return 1;
    }

    std::cout << "All crypto tests passed." << std::endl;
    return 0;
}
