/** @file Answer.hpp @brief DNS 应答扫描与查询关联接口。 */
#pragma once

#include <Prism/Net/Dns/AnswerSet.hpp>
#include <Prism/Net/Dns/Format.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/ip/address.hpp>

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

namespace Prism::Network::Dns
{
    /**
     * @brief 同步纯扫描，仅按 Type 提取 answer 地址，不证明实际 query 关联。
     * @param Data 完整 wire 报文，只借用至返回，不含 TCP 前缀。
     * @param Request 真实字节池与待提取类型；不保存池对象的借用。
     * @return 完整拥有的摘要；畸形报文为 ProtocolError，池预算不足为 ResourceUnavailable。
     */
    [[nodiscard]] auto ScanAnswers(std::span<const std::uint8_t> Data,
        AnswerScanRequest Request) -> std::expected<AnswerSet, Fault::Failure>;

    /**
     * @brief 校验生产应答属于完整当前问题，并只发布 query/CNAME 可达的地址。
     * @param Data 当前接收 owner 借用的完整 wire，同步返回后即可归还。
     * @param Request 当前 query 拥有身份和真实池；输入借用仅持续至返回。
     * @return 值结果保留 ID、TC、RCODE、TTL 存在性；错误不抛异常或生成动态文本。
     */
    [[nodiscard]] auto CheckAnswers(std::span<const std::uint8_t> Data,
        CheckedAnswerRequest Request) -> std::expected<AnswerSet, Fault::Failure>;

    /** @brief 完整物化 Message 的离线地址提取；不作为生产 query 关联入口。 */
    [[nodiscard]] auto ExtractIps(const Message &MessageValue)
        -> std::vector<boost::asio::ip::address>;

    /** @brief 返回完整物化 Message 的最小非 OPT TTL；真实零秒仍返回有值 optional。 */
    [[nodiscard]] auto RecordTtl(const Message &MessageValue) noexcept
        -> std::optional<std::uint32_t>;
} // namespace Prism::Network::Dns
