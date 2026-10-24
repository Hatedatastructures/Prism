/** @file Record.hpp @brief DNS 完整报文中的有界 header、question 和记录游标。 */
#pragma once

#include <Prism/Net/Dns/QueryType.hpp>
#include <Prism/Net/Dns/Detail/Name.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <utility>

namespace Prism::Network::Dns::Detail
{
    /** @brief 同步读取的 header 值；各 section 数量只用于当前完整报文。 */
    struct ResponseHeader final
    {
        std::uint16_t Id{0};
        std::uint16_t Flags{0};
        std::uint16_t Questions{0};
        std::uint16_t Answers{0};
        std::uint16_t Authority{0};
        std::uint16_t Additional{0};
    };

    /** @brief 读取固定 header 并限制完整 DNS 报文大小，输入仅同步借用。 */
    [[nodiscard]] auto ReadHeader(const std::span<const std::uint8_t> Data) noexcept
        -> std::expected<ResponseHeader, Fault::Failure>;

    /** @brief 解压后的完整问题值；名称拥有字节，不保存原始输入借用。 */
    struct QuestionView final
    {
        DecodedName Name;
        std::uint16_t Type{0};
        std::uint16_t Class{0};
    };

    [[nodiscard]] auto ReadQuestion(NameCursor &Cursor) noexcept
        -> std::expected<QuestionView, Fault::Failure>;

    /** @brief 同步记录视图；Name 为拥有值，Rdata 只借用当前完整报文。 */
    struct RecordView final
    {
        DecodedName Name;
        std::uint16_t Type{0};
        std::uint16_t Class{0};
        std::uint32_t Ttl{0};
        std::size_t NameOffset{0};
        std::size_t RdataOffset{0};
        std::span<const std::uint8_t> Rdata;
    };

    /** @brief 有界读取记录；Rdata 借用不得逃离当前同步扫描，错误不抛异常。 */
    [[nodiscard]] auto ReadRecord(NameCursor &Cursor) noexcept
        -> std::expected<RecordView, Fault::Failure>;

    /** @brief CNAME RDATA 必须恰好编码一个完整名称，可以回指当前完整报文。 */
    [[nodiscard]] auto ReadCname(const RecordView &Record,
                                 const std::span<const std::uint8_t> Data) noexcept
        -> std::expected<DecodedName, Fault::Failure>;
}
