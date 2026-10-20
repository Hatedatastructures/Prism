/** @file AnswerSet.hpp @brief DNS 完整拥有的应答事实与扫描请求。 */
#pragma once

#include <Prism/Net/Dns/AddressList.hpp>
#include <Prism/Net/Dns/QueryIdentity.hpp>
#include <cstdint>

namespace Prism::Network::Dns
{
    /** @brief 结果独占地址块；TTL 存在性与真实零秒独立，ID 不证明应答关联。 */
    struct AnswerSet final
    {
        std::uint16_t Id{0};
        bool Truncated{false};
        std::uint16_t Rcode{0};
        bool HasTtl{false};
        std::uint32_t MinTtl{0};
        AddressList Ips;
    };

    /** @brief 纯扫描输入，不承诺与实际 query 关联；Type 决定地址提取类型。 */
    struct AnswerScanRequest final
    {
        QType Type;
        Memory::BytePool &Pool;
    };

    /** @brief 正式生产应答输入；同步借用真实 query 身份和池，输出独占实际字节。 */
    struct CheckedAnswerRequest final
    {
        const QueryIdentity &Query;
        Memory::BytePool &Pool;
    };

    /** @brief TTL 合并包含零秒；只有两份结果都没有 TTL 时才保持缺失。 */
    auto MergeTtl(AnswerSet &Target, const AnswerSet &Source) noexcept -> void;
}
