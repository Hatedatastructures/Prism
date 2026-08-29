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

    namespace net = boost::asio;

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
        boost::container::small_vector<net::ip::address, 8> Ips; ///< Answer 段中 qtype 匹配的地址
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
        [[nodiscard]] inline auto SkipName(std::span<const std::uint8_t> data, std::size_t &off)
            -> bool
        {
            std::size_t Cur = off;
            std::size_t NextOff = off;
            bool Jumped = false;
            std::size_t Jumps = 0;

            while (true)
            {
                if (Cur >= data.size())
                {
                    return false;
                }
                const auto Len = data[Cur];
                if ((Len & 0xC0) == 0xC0)
                {
                    if (Cur + 2 > data.size())
                    {
                        return false;
                    }
                    if (!Jumped)
                    {
                        NextOff = Cur + 2;
                        Jumped = true;
                    }
                    if (++Jumps > MaxNameJumps)
                    {
                        return false; // 压缩指针循环
                    }
                    Cur = (static_cast<std::size_t>(Len & 0x3F) << 8) | data[Cur + 1];
                    continue;
                }
                if (Len == 0)
                {
                    if (!Jumped)
                    {
                        NextOff = Cur + 1;
                    }
                    break;
                }
                if (Cur + 1 + Len > data.size())
                {
                    return false;
                }
                Cur += 1 + Len;
            }
            off = NextOff;
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
    [[nodiscard]] inline auto ScanAnswers(std::span<const std::uint8_t> data,
                                          const std::uint16_t qtype)
        -> std::optional<AnswerSet>
    {
        if (data.size() < 12)
        {
            return std::nullopt;
        }
        AnswerSet out;
        out.Id = static_cast<std::uint16_t>((data[0] << 8) | data[1]);
        const auto Flags = static_cast<std::uint16_t>((data[2] << 8) | data[3]);
        out.Truncated = (Flags & 0x0200u) != 0;
        out.Rcode = static_cast<std::uint8_t>(Flags & 0x0Fu);

        const auto QdCount = static_cast<std::uint16_t>((data[4] << 8) | data[5]);
        const auto AnCount = static_cast<std::uint16_t>((data[6] << 8) | data[7]);
        const auto NsCount = static_cast<std::uint16_t>((data[8] << 8) | data[9]);
        const auto ArCount = static_cast<std::uint16_t>((data[10] << 8) | data[11]);

        std::size_t off = 12;

        // 跳过 Question 段（QNAME + QTYPE + QCLASS）
        for (std::uint16_t i = 0; i < QdCount; ++i)
        {
            if (!Detail::SkipName(data, off))
            {
                return std::nullopt;
            }
            const auto Fixed = Detail::GetU16(data, off) && Detail::GetU16(data, off);
            if (!Fixed)
            {
                return std::nullopt;
            }
        }

        // 三段记录：Answer 收集地址，三段共同参与 MinTtl
        bool HasTtl = false;
        const auto ScanSection = [&](const std::uint16_t count, const bool collect) -> bool
        {
            for (std::uint16_t i = 0; i < count; ++i)
            {
                if (!Detail::SkipName(data, off))
                {
                    return false;
                }
                const auto Type = Detail::GetU16(data, off);
                const auto RClass = Detail::GetU16(data, off);
                const auto Ttl = Detail::GetU32(data, off);
                const auto RdLength = Detail::GetU16(data, off);
                if (!Type || !RClass || !Ttl || !RdLength)
                {
                    return false;
                }
                if (off + *RdLength > data.size())
                {
                    return false;
                }
                // OPT（type 41）的 TTL 字段实为扩展标志位（RFC 6891），不参与最小 TTL
                if (*Type != static_cast<std::uint16_t>(QType::Opt))
                {
                    out.MinTtl = HasTtl ? std::min(out.MinTtl, *Ttl) : *Ttl;
                    HasTtl = true;
                }
                if (collect && *Type == qtype)
                {
                    if (*Type == static_cast<std::uint16_t>(QType::A) && *RdLength == 4)
                    {
                        const auto Raw = (static_cast<std::uint32_t>(data[off]) << 24) |
                                         (static_cast<std::uint32_t>(data[off + 1]) << 16) |
                                         (static_cast<std::uint32_t>(data[off + 2]) << 8) |
                                         static_cast<std::uint32_t>(data[off + 3]);
                        out.Ips.emplace_back(net::ip::address_v4(Raw));
                    }
                    else if (*Type == static_cast<std::uint16_t>(QType::Aaaa) && *RdLength == 16)
                    {
                        std::array<unsigned char, 16> Bytes{};
                        for (std::size_t b = 0; b < Bytes.size(); ++b)
                        {
                            Bytes[b] = data[off + b];
                        }
                        out.Ips.emplace_back(net::ip::address_v6(Bytes));
                    }
                    // 类型匹配但 rdlength 非法：与 ExtractIps 语义一致，跳过该记录
                }
                off += *RdLength;
            }
            return true;
        };

        if (!ScanSection(AnCount, true) || !ScanSection(NsCount, false) ||
            !ScanSection(ArCount, false))
        {
            return std::nullopt;
        }
        return out;
    }

} // namespace Preview::Network::Dns
