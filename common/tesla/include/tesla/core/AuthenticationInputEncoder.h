#pragma once

#include "tesla/core/AuthenticationPacketInput.h"
#include "tesla/crypto/CryptoTypes.h"

#include <cstdint>
#include <string>
#include <vector>

namespace tesla::core
{
/**
 * @brief 将TESLA逻辑字段编码为密码算法的确定性输入字节串。
 *
 * 所有整数使用大端序。本类只定义MAC/HMAC输入格式，不承担UDP报文编解码。
 */
class AuthenticationInputEncoder final
{
public:
    /**
     * @brief 编码单包MAC输入。
     * @param pktInput 已验证的单包逻辑输入。
     * @return 按Sender、链、间隔、报文索引和消息顺序编码的字节串。
     */
    static crypto::ByteBuffer vecEncodePacketMacInput(
        const AuthenticationPacketInput& pktInput
    );

    /**
     * @brief 编码完整报文组的快速组标签输入。
     * @param grpInput 不含缺失槽位的报文组。
     * @param vecSamdTau 与当前KS+RS矩阵对应的SAMD标签。
     * @return 包含组上下文、全部报文及SAMD标签的确定性字节串。
     * @throws std::invalid_argument 组内存在缺失报文或标签数量不可编码时抛出。
     */
    static crypto::ByteBuffer vecEncodeFastGroupInput(
        const AuthenticationGroupInput& grpInput,
        const std::vector<crypto::Digest>& vecSamdTau
    );

private:
    AuthenticationInputEncoder() = delete;

    static void appendBytes(crypto::ByteBuffer& vecOutput, const std::uint8_t* pData, std::size_t nSize);
    static void appendSenderId(crypto::ByteBuffer& vecOutput, const std::string& strSenderId);
    static void appendUint16(crypto::ByteBuffer& vecOutput, std::uint16_t u16Value);
    static void appendUint32(crypto::ByteBuffer& vecOutput, std::uint32_t u32Value);
    static void appendUint64(crypto::ByteBuffer& vecOutput, std::uint64_t u64Value);
};
}
