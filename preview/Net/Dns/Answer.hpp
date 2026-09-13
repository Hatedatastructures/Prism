/**
 * @file Answer.hpp
 * @brief DNS 应答热路径扫描器
 * @details 对齐主项目 net/dns/detail/format 分层，但只做热路径需要的事：
 *          单遍扫描 wire bytes 提取 {Id, TC, RCODE, 最小 TTL, A/AAAA 地址}，
 *          不物化 Question/Record 结构（owner name 只推进偏移、不构造字符串），
 *          地址内联存放（small_vector），典型应答全程 0 次堆分配。
 *          完整报文物化仍由 Format.hpp 的 Message::Unpack 提供（测试/golden 路径）。
 * @note Ips 仅收集 Answer 段中类型匹配 qtype 的记录；MinTtl 语义与
 *       Message::MinTtl 一致（Answer/Authority/Additional 三段最小值）
 */

#pragma once

#include "Format.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/container/small_vector.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace Preview::Network::Dns
{

    namespace Net = boost::asio;

    /**
     * @struct AnswerSet
     * @brief 热路径应答摘要
     */
    struct AnswerSet
    {
        std::uint16_t Id{0};                                 ///< 报文标识（调用方比对查询 Id）
        bool Truncated{false};                               ///< TC 截断标志
        std::uint8_t Rcode{0};                               ///< 响应码（0=NOERROR, 3=NXDOMAIN）
        std::uint32_t MinTtl{0};                             ///< 三段记录最小 TTL（无记录为 0）
        boost::container::small_vector<Net::ip::address, 8> Ips; ///< Answer 段中 qtype 匹配的地址
    };

    namespace Detail
    {
        /**
         * @brief 跳过报文中的一个域名（处理压缩指针）
         * @details 与 DecodeName 的遍历规则一致，但只推进偏移、不构造字符串。
         * @param data 完整报文
         * @param off [in/out] 域名起始偏移；成功后推进到名字之后第一个字节
         * @return 非法输入（越界/指针循环）返回 false
         */
        [[nodiscard]] inline auto SkipName(std::span<const std::uint8_t> Data, std::size_t &Offset)
            -> bool
        {
            std::size_t Current = Offset;
            std::size_t NextOffset = Offset;
            bool Jumped = false;
            std::size_t Jumps = 0;

            while (true)
            {
                if (Current >= Data.size())
                {
                    return false;
                }
                const auto Len = Data[Current];
                if ((Len & 0xC0) == 0xC0)
                {
                    if (Current + 2 > Data.size())
                    {
                        return false;
                    }
                    if (!Jumped)
                    {
                        NextOffset = Current + 2;
                        Jumped = true;
                    }
                    if (++Jumps > MaxNameJumps)
                    {
                        return false; // 压缩指针循环
                    }
                    Current = (static_cast<std::size_t>(Len & 0x3F) << 8) | Data[Current + 1];
                    continue;
                }
                if (Len == 0)
                {
                    if (!Jumped)
                    {
                        NextOffset = Current + 1;
                    }
                    break;
                }
                if (Current + 1 + Len > Data.size())
                {
                    return false;
                }
                Current += 1 + Len;
            }
            Offset = NextOffset;
            return true;
        }
    } // namespace Detail

    /**
     * @brief 单遍扫描 DNS 应答，提取热路径所需摘要
     * @param data wire bytes（UDP 数据报或 TCP 帧体，不含帧前缀）
     * @param qtype 期望的记录类型（A 或 AAAA）；Answer 段中该类型的
     *              记录被收集为地址，其余类型跳过
     * @return 畸形输入（长度不足/字段越界/压缩指针循环/记录越界）返回 nullopt
     */
    [[nodiscard]] inline auto ScanAnswers(std::span<const std::uint8_t> Data,
                                          const std::uint16_t QTypeValue)
        -> std::optional<AnswerSet>
    {
        if (Data.size() < 12)
        {
            return std::nullopt;
        }
        AnswerSet Result;
        Result.Id = static_cast<std::uint16_t>((Data[0] << 8) | Data[1]);
        const auto Flags = static_cast<std::uint16_t>((Data[2] << 8) | Data[3]);
        Result.Truncated = (Flags & 0x0200u) != 0;
        Result.Rcode = static_cast<std::uint8_t>(Flags & 0x0Fu);

        const auto QdCount = static_cast<std::uint16_t>((Data[4] << 8) | Data[5]);
        const auto AnCount = static_cast<std::uint16_t>((Data[6] << 8) | Data[7]);
        const auto NsCount = static_cast<std::uint16_t>((Data[8] << 8) | Data[9]);
        const auto ArCount = static_cast<std::uint16_t>((Data[10] << 8) | Data[11]);

        std::size_t Offset = 12;

        // 跳过 Question 段（QNAME + QTYPE + QCLASS）
        for (std::uint16_t Index = 0; Index < QdCount; ++Index)
        {
            if (!Detail::SkipName(Data, Offset))
            {
                return std::nullopt;
            }
            const auto Fixed = Detail::GetU16(Data, Offset) && Detail::GetU16(Data, Offset);
            if (!Fixed)
            {
                return std::nullopt;
            }
        }

        // 三段记录：Answer 收集地址，三段共同参与 MinTtl
        bool HasTtl = false;
        const auto ScanSection = [&](const std::uint16_t Count, const bool Collect) -> bool
        {
            for (std::uint16_t Index = 0; Index < Count; ++Index)
            {
                if (!Detail::SkipName(Data, Offset))
                {
                    return false;
                }
                const auto Type = Detail::GetU16(Data, Offset);
                const auto RClass = Detail::GetU16(Data, Offset);
                const auto Ttl = Detail::GetU32(Data, Offset);
                const auto RdLength = Detail::GetU16(Data, Offset);
                if (!Type || !RClass || !Ttl || !RdLength)
                {
                    return false;
                }
                if (Offset + *RdLength > Data.size())
                {
                    return false;
                }
                // OPT（type 41）的 TTL 字段实为扩展标志位（RFC 6891），不参与最小 TTL
                if (*Type != static_cast<std::uint16_t>(QType::Opt))
                {
                    if (HasTtl)
                    {
                        Result.MinTtl = std::min(Result.MinTtl, *Ttl);
                    }
                    else
                    {
                        Result.MinTtl = *Ttl;
                    }
                    HasTtl = true;
                }
                if (Collect && *Type == QTypeValue)
                {
                    if (*Type == static_cast<std::uint16_t>(QType::A) && *RdLength == 4)
                    {
                        const auto Raw = (static_cast<std::uint32_t>(Data[Offset]) << 24) |
                                         (static_cast<std::uint32_t>(Data[Offset + 1]) << 16) |
                                         (static_cast<std::uint32_t>(Data[Offset + 2]) << 8) |
                                         static_cast<std::uint32_t>(Data[Offset + 3]);
                        Result.Ips.emplace_back(Net::ip::address_v4(Raw));
                    }
                    else if (*Type == static_cast<std::uint16_t>(QType::Aaaa) && *RdLength == 16)
                    {
                        std::array<unsigned char, 16> Bytes{};
                        for (std::size_t b = 0; b < Bytes.size(); ++b)
                        {
                            Bytes[b] = Data[Offset + b];
                        }
                        Result.Ips.emplace_back(Net::ip::address_v6(Bytes));
                    }
                    // 类型匹配但 rdlength 非法：与 ExtractIps 语义一致，跳过该记录
                }
                Offset += *RdLength;
            }
            return true;
        };

        if (!ScanSection(AnCount, true) || !ScanSection(NsCount, false) ||
            !ScanSection(ArCount, false))
        {
            return std::nullopt;
        }
        return Result;
    }

} // namespace Preview::Network::Dns
