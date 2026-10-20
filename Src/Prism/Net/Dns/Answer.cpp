/** @file Answer.cpp @brief DNS 应答扫描与查询关联实现。 */
#include <Prism/Net/Dns/Answer.hpp>

#include "Detail/CheckedAnswer.hpp"
#include "Detail/Scan.hpp"

#include <array>

namespace Prism::Network::Dns
{
    auto MergeTtl(AnswerSet &Target, const AnswerSet &Source) noexcept -> void
    {
        if (!Source.HasTtl)
        {
            return;
        }
        if (!Target.HasTtl || Source.MinTtl < Target.MinTtl)
        {
            Target.MinTtl = Source.MinTtl;
        }
        Target.HasTtl = true;
    }

    auto ScanAnswers(const std::span<const std::uint8_t> Data,
        const AnswerScanRequest Request) -> std::expected<AnswerSet, Fault::Failure>
    {
        return Detail::ScanResponse(Data, Request);
    }

    auto CheckAnswers(const std::span<const std::uint8_t> Data,
        const CheckedAnswerRequest Request) -> std::expected<AnswerSet, Fault::Failure>
    {
        return Detail::CheckResponse(Data, Request);
    }

    auto ExtractIps(const Message &MessageValue)
        -> std::vector<boost::asio::ip::address>
    {
        std::vector<boost::asio::ip::address> Ips;
        Ips.reserve(MessageValue.Answers.size());
        for (const auto &RecordValue : MessageValue.Answers)
        {
            if (const auto V4 = ExtractIpv4(RecordValue))
            {
                Ips.emplace_back(*V4);
            }
            else if (const auto V6 = ExtractIpv6(RecordValue))
            {
                Ips.emplace_back(*V6);
            }
        }
        return Ips;
    }

    auto RecordTtl(const Message &MessageValue) noexcept -> std::optional<std::uint32_t>
    {
        std::optional<std::uint32_t> Best;
        const std::array<const std::vector<Record> *, 3> Sections{
            &MessageValue.Answers, &MessageValue.Authority, &MessageValue.Additional};
        for (const auto *Section : Sections)
        {
            for (const auto &RecordValue : *Section)
            {
                if (RecordValue.Type == QType::Opt)
                {
                    continue;
                }
                if (!Best || RecordValue.Ttl < *Best)
                {
                    Best = RecordValue.Ttl;
                }
            }
        }
        return Best;
    }
} // namespace Prism::Network::Dns
