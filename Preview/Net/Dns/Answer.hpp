/**
 * @file Answer.hpp
 * @brief DNS 纯扫描与正式 query 关联的稳定值前门。
 * @details ScanAnswers 是 codec 工具，CheckAnswers 才是上游生产应答的关联入口。
 *          两者消费同一有界名称/记录读取器，输出独占可回收地址存储。
 */
#pragma once

#include <Preview/Net/Dns/AnswerSet.hpp>
#include <Preview/Net/Dns/Detail/CheckedAnswer.hpp>
#include <Preview/Net/Dns/Detail/Scan.hpp>
#include <Preview/Net/Dns/Format.hpp>

#include <algorithm>
#include <array>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace Preview::Network::Dns
{
    /**
     * @brief 同步纯扫描，仅按 Type 提取 answer 地址，不证明实际 query 关联。
     * @param Data 完整 wire 报文，只借用至返回，不含 TCP 前缀。
     * @param Request 真实字节池与待提取类型；不保存池对象的借用。
     * @return 完整拥有的摘要；畸形报文为 ProtocolError，池预算不足为 ResourceUnavailable。
     * @details 无 executor、取消、半关闭或关闭；输出 lease 保活实际 allocator 状态。
     */
    [[nodiscard]] inline auto ScanAnswers(const std::span<const std::uint8_t> Data,
        const AnswerScanRequest Request) -> std::expected<AnswerSet, Fault::Failure>
    {
        return Detail::ScanResponse(Data, Request);
    }

    /**
     * @brief 校验生产应答属于完整当前问题，并只发布 query/CNAME 可达的地址。
     * @param Data 当前接收 owner 借用的完整 wire，同步返回后即可归还。
     * @param Request 当前 query 拥有身份和真实池；输入借用仅持续至返回。
     * @return 值结果保留 ID、TC、RCODE、TTL 存在性；错误不抛异常或生成动态文本。
     * @details 取消和网络/timeout 错误由 I/O owner 原样传递，不能包装成解析错误。
     */
    [[nodiscard]] inline auto CheckAnswers(const std::span<const std::uint8_t> Data,
        const CheckedAnswerRequest Request) -> std::expected<AnswerSet, Fault::Failure>
    {
        return Detail::CheckResponse(Data, Request);
    }

    /** @brief 完整物化 Message 的离线地址提取；不作为生产 query 关联入口。 */
    [[nodiscard]] inline auto ExtractIps(const Message& MessageValue) -> std::vector<boost::asio::ip::address>
    {
        std::vector<boost::asio::ip::address> Ips;
        Ips.reserve(MessageValue.Answers.size());
        for (const auto& RecordValue : MessageValue.Answers)
        {
            if (auto V4 = ExtractIpv4(RecordValue))
                Ips.emplace_back(*V4);
            else if (auto V6 = ExtractIpv6(RecordValue))
                Ips.emplace_back(*V6);
        }
        return Ips;
    }

    /** @brief 返回完整物化 Message 的 TTL 存在值；真实零秒仍返回有值 optional。 */
    [[nodiscard]] inline auto RecordTtl(const Message& MessageValue) noexcept -> std::optional<std::uint32_t>
    {
        std::optional<std::uint32_t> Best;
        const std::array<const std::vector<Record>*, 3> Sections{&MessageValue.Answers,
            &MessageValue.Authority, &MessageValue.Additional};
        for (const auto* Section : Sections)
        {
            for (const auto& RecordValue : *Section)
            {
                if (RecordValue.Type == QType::Opt)
                    continue;
                if (!Best || RecordValue.Ttl < *Best)
                    Best = RecordValue.Ttl;
            }
        }
        return Best;
    }
} // namespace Preview::Network::Dns
