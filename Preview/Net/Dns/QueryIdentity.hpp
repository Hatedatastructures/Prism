/** @file QueryIdentity.hpp @brief DNS 当前问题的拥有型身份与有界 wire 构造。 */
#pragma once

#include <Preview/Net/DomainName.hpp>
#include <Preview/Net/Dns/QueryType.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <utility>

namespace Preview::Network::Dns
{
    /** @brief 当前 query 的协议参数；Id 必须由真实上游 owner 的在途预约取得。 */
    struct QueryParameters final
    {
        std::uint16_t Id{0};
        QType Type{QType::A};
        std::uint16_t Class{1};
        std::uint8_t Opcode{0};
    };

    /**
     * @brief 拥有规范化完整问题名、ID、type、class 和 opcode 的不可借用输入事实。
     * @details 由异步查询 owner 持有至所有 I/O 退栈；普通查询仅支持标准 opcode 和 IN 类。
     *          本值不持 socket、executor 或取消节点，ID 退休由 QueryIdReservation 负责。
     */
    struct QueryIdentity final
    {
        DomainName Name;
        QueryParameters Parameters;

        QueryIdentity(DomainName Domain, const QueryParameters Params) noexcept
            : Name(std::move(Domain)), Parameters(Params) {}

        /**
         * @brief 把标准递归 query 写入调用者已有容量，不分配或部分发布报文。
         * @param Output 同步借用可写缓冲区；有效最大容量为 271 字节。
         * @return 非 IN/标准查询为 InvalidArgument，容量不足为 ResourceUnavailable；成功返回实际长度。
         */
        [[nodiscard]] auto Encode(const std::span<std::uint8_t> Output) const noexcept
            -> std::expected<std::size_t, Fault::Failure>
        {
            if (Parameters.Class != 1 || Parameters.Opcode != 0)
                return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument, {}});
            const auto Text = Name.View();
            const auto Required = 12 + Text.size() + 2 + 4;
            if (Output.size() < Required)
                return std::unexpected(Fault::Failure{Fault::Code::ResourceUnavailable, {}});
            for (std::size_t Index = 0; Index < 12; ++Index) Output[Index] = 0;
            Output[0] = static_cast<std::uint8_t>(Parameters.Id >> 8);
            Output[1] = static_cast<std::uint8_t>(Parameters.Id);
            Output[2] = 1;
            Output[5] = 1;
            std::size_t Offset = 12;
            std::size_t Start = 0;
            while (Start < Text.size())
            {
                auto End = Text.find('.', Start);
                if (End == std::string_view::npos) End = Text.size();
                Output[Offset++] = static_cast<std::uint8_t>(End - Start);
                for (std::size_t Index = Start; Index < End; ++Index)
                    Output[Offset++] = static_cast<std::uint8_t>(Text[Index]);
                Start = End + 1;
            }
            Output[Offset++] = 0;
            const auto Type = static_cast<std::uint16_t>(Parameters.Type);
            Output[Offset++] = static_cast<std::uint8_t>(Type >> 8);
            Output[Offset++] = static_cast<std::uint8_t>(Type);
            Output[Offset++] = 0;
            Output[Offset++] = 1;
            return Offset;
        }
    };
}
