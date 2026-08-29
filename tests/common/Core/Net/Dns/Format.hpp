/**
 * @file Format.hpp
 * @brief DNS 报文编解码层（RFC 1035）
 * @details DNS 二进制报文的构造与解析，完全不依赖系统 resolver，对齐主项目
 *          net/dns/detail/format.hpp 分层。支持：
 *          - 域名压缩指针编码（compression map）与解码（跳转循环检测）
 *          - Header / Question / Answer / Authority / Additional 全段编解码
 *          - A/AAAA/CNAME/NS/MX/TXT/SOA/OPT 记录类型
 *          - TCP 2 字节长度前缀帧封装（PackTcp / UnpackTcp）
 * @note rdata 保持原始字节（不做 rdata 内部域名压缩），A/AAAA 的 rdata 为
 *       裸 4/16 字节地址，与主项目行为一致
 */

#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace Preview::Network::Dns
{

    /**
     * @enum QType
     * @brief DNS 查询/资源记录类型（RFC 1035 QTYPE / TYPE 字段）
     */
    enum class QType : std::uint16_t
    {
        A = 1,     ///< IPv4 地址记录
        Ns = 2,    ///< 权威名称服务器
        Cname = 5, ///< 规范名称（别名）
        Soa = 6,   ///< 区域起始授权
        Mx = 15,   ///< 邮件交换
        Txt = 16,  ///< 文本记录
        Aaaa = 28, ///< IPv6 地址记录
        Opt = 41,  ///< EDNS0 选项
    };

    /**
     * @struct Question
     * @brief DNS 查询段
     */
    struct Question
    {
        std::string Name;      ///< 域名，小写无末尾点号
        QType QueryType{};     ///< 查询类型
        std::uint16_t QClass{1}; ///< 查询类，默认 IN（Internet）
    };

    /**
     * @struct Record
     * @brief DNS 资源记录
     */
    struct Record
    {
        std::string Name;             ///< 拥有者名称，小写无末尾点号
        QType Type{};                 ///< 记录类型
        std::uint16_t RClass{1};      ///< 记录类，默认 IN
        std::uint32_t Ttl{0};         ///< 生存时间（秒）
        std::vector<std::uint8_t> Rdata; ///< 原始 RDATA 字节
    };

    /**
     * @brief 从 A 记录提取 IPv4 地址
     * @param rec DNS 资源记录
     * @return rdata 恰好 4 字节时返回对应地址，否则 nullopt
     */
    [[nodiscard]] inline auto ExtractIpv4(const Record &rec) -> std::optional<boost::asio::ip::address_v4>
    {
        if (rec.Type != QType::A || rec.Rdata.size() != 4)
        {
            return std::nullopt;
        }
        const auto Raw = static_cast<std::uint32_t>(rec.Rdata[0]) << 24 |
                         static_cast<std::uint32_t>(rec.Rdata[1]) << 16 |
                         static_cast<std::uint32_t>(rec.Rdata[2]) << 8 |
                         static_cast<std::uint32_t>(rec.Rdata[3]);
        return boost::asio::ip::address_v4(Raw);
    }

    /**
     * @brief 从 AAAA 记录提取 IPv6 地址
     * @param rec DNS 资源记录
     * @return rdata 恰好 16 字节时返回对应地址，否则 nullopt
     */
    [[nodiscard]] inline auto ExtractIpv6(const Record &rec) -> std::optional<boost::asio::ip::address_v6>
    {
        if (rec.Type != QType::Aaaa || rec.Rdata.size() != 16)
        {
            return std::nullopt;
        }
        std::array<unsigned char, 16> Bytes{};
        std::memcpy(Bytes.data(), rec.Rdata.data(), Bytes.size());
        return boost::asio::ip::address_v6(Bytes);
    }

    namespace Detail
    {
        /// 大端写入 16 位整数
        inline void PutU16(std::vector<std::uint8_t> &out, const std::uint16_t v)
        {
            out.push_back(static_cast<std::uint8_t>(v >> 8));
            out.push_back(static_cast<std::uint8_t>(v & 0xFF));
        }

        /// 大端写入 32 位整数
        inline void PutU32(std::vector<std::uint8_t> &out, const std::uint32_t v)
        {
            out.push_back(static_cast<std::uint8_t>(v >> 24));
            out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
            out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
            out.push_back(static_cast<std::uint8_t>(v & 0xFF));
        }

        /// 大端读取 16 位整数；缓冲区不足返回 nullopt
        [[nodiscard]] inline auto GetU16(std::span<const std::uint8_t> data, std::size_t &off)
            -> std::optional<std::uint16_t>
        {
            if (off + 2 > data.size())
            {
                return std::nullopt;
            }
            const auto v = static_cast<std::uint16_t>((data[off] << 8) | data[off + 1]);
            off += 2;
            return v;
        }

        /// 大端读取 32 位整数；缓冲区不足返回 nullopt
        [[nodiscard]] inline auto GetU32(std::span<const std::uint8_t> data, std::size_t &off)
            -> std::optional<std::uint32_t>
        {
            if (off + 4 > data.size())
            {
                return std::nullopt;
            }
            const auto v = (static_cast<std::uint32_t>(data[off]) << 24) |
                           (static_cast<std::uint32_t>(data[off + 1]) << 16) |
                           (static_cast<std::uint32_t>(data[off + 2]) << 8) |
                           static_cast<std::uint32_t>(data[off + 3]);
            off += 4;
            return v;
        }

        /// 域名压缩指针循环跳转上限
        constexpr std::size_t MaxNameJumps = 128;

        /**
         * @brief 编码域名字节序列（带压缩指针）
         * @details 从完整域名开始逐级后缀查压缩表：命中则写 2 字节指针
         *          （0xC000 | offset）并结束；未命中写 "长度+标签" 并把当前
         *          后缀登记进压缩表（offset 必须落在 14 位可表示范围内）。
         * @param out 输出字节流
         * @param name 小写无末尾点号域名
         * @param map 压缩表（后缀 → 报文内偏移）
         */
        inline void AppendName(std::vector<std::uint8_t> &out, std::string_view name,
                               std::unordered_map<std::string, std::uint16_t> &map)
        {
            while (!name.empty())
            {
                if (const auto It = map.find(std::string(name)); It != map.end())
                {
                    const auto Ptr = static_cast<std::uint16_t>(0xC000u | It->second);
                    PutU16(out, Ptr);
                    return;
                }
                if (out.size() <= 0x3FFF)
                {
                    map.emplace(std::string(name), static_cast<std::uint16_t>(out.size()));
                }
                const auto Dot = name.find('.');
                const auto Label = Dot == std::string_view::npos ? name : name.substr(0, Dot);
                if (Label.empty() || Label.size() > 63)
                {
                    return; // 非法标签：丢弃尾部（调用方应保证输入已规范化）
                }
                out.push_back(static_cast<std::uint8_t>(Label.size()));
                out.insert(out.end(), Label.begin(), Label.end());
                if (Dot == std::string_view::npos)
                {
                    break;
                }
                name = name.substr(Dot + 1);
            }
            out.push_back(0);
        }

        /**
         * @brief 从报文解码域名（处理压缩指针）
         * @param data 完整报文
         * @param off [in/out] 解码起始偏移；成功后推进到名字之后的第一个字节
         * @return 小写无末尾点号域名；畸形输入（越界/循环/超长）返回 nullopt
         */
        [[nodiscard]] inline auto DecodeName(std::span<const std::uint8_t> data, std::size_t &off)
            -> std::optional<std::string>
        {
            std::string Labels;
            std::size_t Cur = off;
            std::size_t NextOff = off;
            bool Jumped = false;
            std::size_t Jumps = 0;

            while (true)
            {
                if (Cur >= data.size())
                {
                    return std::nullopt;
                }
                const auto Len = data[Cur];
                if ((Len & 0xC0) == 0xC0)
                {
                    if (Cur + 2 > data.size())
                    {
                        return std::nullopt;
                    }
                    if (!Jumped)
                    {
                        NextOff = Cur + 2;
                        Jumped = true;
                    }
                    if (++Jumps > MaxNameJumps)
                    {
                        return std::nullopt; // 压缩指针循环
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
                if (Cur + 1 + Len > data.size() || Labels.size() + Len + 1 > 255)
                {
                    return std::nullopt;
                }
                if (!Labels.empty())
                {
                    Labels += '.';
                }
                Labels.append(reinterpret_cast<const char *>(data.data() + Cur + 1), Len);
                Cur += 1 + Len;
            }
            off = NextOff;
            return Labels;
        }

        /// 编码单条资源记录（name 参与压缩，rdata 原样写入）
        inline void AppendRecord(std::vector<std::uint8_t> &out, const Record &rec,
                                 std::unordered_map<std::string, std::uint16_t> &map)
        {
            AppendName(out, rec.Name, map);
            PutU16(out, static_cast<std::uint16_t>(rec.Type));
            PutU16(out, rec.RClass);
            PutU32(out, rec.Ttl);
            PutU16(out, static_cast<std::uint16_t>(rec.Rdata.size()));
            out.insert(out.end(), rec.Rdata.begin(), rec.Rdata.end());
        }

        /// 从报文解码单条资源记录
        [[nodiscard]] inline auto DecodeRecord(std::span<const std::uint8_t> data, std::size_t &off)
            -> std::optional<Record>
        {
            auto Name = DecodeName(data, off);
            if (!Name)
            {
                return std::nullopt;
            }
            auto Type = GetU16(data, off);
            auto RClass = GetU16(data, off);
            auto Ttl = GetU32(data, off);
            auto RdLength = GetU16(data, off);
            if (!Type || !RClass || !Ttl || !RdLength)
            {
                return std::nullopt;
            }
            if (off + *RdLength > data.size())
            {
                return std::nullopt;
            }
            Record rec;
            rec.Name = std::move(*Name);
            rec.Type = static_cast<QType>(*Type);
            rec.RClass = *RClass;
            rec.Ttl = *Ttl;
            rec.Rdata.assign(data.begin() + static_cast<std::ptrdiff_t>(off),
                             data.begin() + static_cast<std::ptrdiff_t>(off + *RdLength));
            off += *RdLength;
            return rec;
        }
    } // namespace Detail

    /**
     * @class Message
     * @brief DNS 报文（RFC 1035 完整结构）
     * @details 包含 Header 与 Question/Answer/Authority/Additional 四段，
     *          提供序列化（Pack）与反序列化（Unpack），域名编码采用压缩指针。
     * @note id 默认为 0，发送前由 Upstream 层设置
     */
    class Message
    {
    public:
        std::uint16_t Id{0};    ///< 报文标识
        bool Qr{false};         ///< 0=查询, 1=响应
        std::uint8_t Opcode{0}; ///< 操作码（0=标准查询）
        bool Aa{false};         ///< 权威应答
        bool Tc{false};         ///< 截断标志
        bool Rd{false};         ///< 期望递归
        bool Ra{false};         ///< 可用递归
        std::uint8_t Rcode{0};  ///< 响应码（0=NOERROR, 3=NXDOMAIN）

        std::vector<Question> Questions;   ///< 查询段
        std::vector<Record> Answers;       ///< 应答段
        std::vector<Record> Authority;     ///< 权威段
        std::vector<Record> Additional;    ///< 附加段

        /**
         * @brief 序列化为 DNS wire format
         * @return 完整二进制报文（Header → Question → 三段记录，域名压缩）
         */
        [[nodiscard]] auto Pack() const -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out;
            out.reserve(512);
            Detail::PutU16(out, Id);

            const auto Flags = static_cast<std::uint16_t>(
                (Qr ? 0x8000u : 0u) | ((Opcode & 0x0Fu) << 11) | (Aa ? 0x0400u : 0u) |
                (Tc ? 0x0200u : 0u) | (Rd ? 0x0100u : 0u) | (Ra ? 0x0080u : 0u) | (Rcode & 0x0Fu));
            Detail::PutU16(out, Flags);
            Detail::PutU16(out, static_cast<std::uint16_t>(Questions.size()));
            Detail::PutU16(out, static_cast<std::uint16_t>(Answers.size()));
            Detail::PutU16(out, static_cast<std::uint16_t>(Authority.size()));
            Detail::PutU16(out, static_cast<std::uint16_t>(Additional.size()));

            std::unordered_map<std::string, std::uint16_t> map;
            for (const auto &q : Questions)
            {
                Detail::AppendName(out, q.Name, map);
                Detail::PutU16(out, static_cast<std::uint16_t>(q.QueryType));
                Detail::PutU16(out, q.QClass);
            }
            for (const auto &r : Answers)
            {
                Detail::AppendRecord(out, r, map);
            }
            for (const auto &r : Authority)
            {
                Detail::AppendRecord(out, r, map);
            }
            for (const auto &r : Additional)
            {
                Detail::AppendRecord(out, r, map);
            }
            return out;
        }

        /**
         * @brief 从二进制数据反序列化 DNS 报文
         * @param data 报文字节缓冲区
         * @return 解析成功返回 Message；长度不足/字段越界/压缩指针循环返回 nullopt
         */
        [[nodiscard]] static auto Unpack(std::span<const std::uint8_t> data) -> std::optional<Message>
        {
            if (data.size() < 12)
            {
                return std::nullopt;
            }
            Message m;
            m.Id = static_cast<std::uint16_t>((data[0] << 8) | data[1]);
            const auto Flags = static_cast<std::uint16_t>((data[2] << 8) | data[3]);
            m.Qr = (Flags & 0x8000u) != 0;
            m.Opcode = static_cast<std::uint8_t>((Flags >> 11) & 0x0Fu);
            m.Aa = (Flags & 0x0400u) != 0;
            m.Tc = (Flags & 0x0200u) != 0;
            m.Rd = (Flags & 0x0100u) != 0;
            m.Ra = (Flags & 0x0080u) != 0;
            m.Rcode = static_cast<std::uint8_t>(Flags & 0x0Fu);

            const auto QdCount = static_cast<std::uint16_t>((data[4] << 8) | data[5]);
            const auto AnCount = static_cast<std::uint16_t>((data[6] << 8) | data[7]);
            const auto NsCount = static_cast<std::uint16_t>((data[8] << 8) | data[9]);
            const auto ArCount = static_cast<std::uint16_t>((data[10] << 8) | data[11]);

            std::size_t off = 12;
            for (std::uint16_t i = 0; i < QdCount; ++i)
            {
                auto Name = Detail::DecodeName(data, off);
                auto Type = Detail::GetU16(data, off);
                auto QClass = Detail::GetU16(data, off);
                if (!Name || !Type || !QClass)
                {
                    return std::nullopt;
                }
                Question q;
                q.Name = std::move(*Name);
                q.QueryType = static_cast<QType>(*Type);
                q.QClass = *QClass;
                m.Questions.push_back(std::move(q));
            }
            const auto ReadRecords = [&](std::uint16_t count, std::vector<Record> &into) -> bool
            {
                for (std::uint16_t i = 0; i < count; ++i)
                {
                    auto rec = Detail::DecodeRecord(data, off);
                    if (!rec)
                    {
                        return false;
                    }
                    into.push_back(std::move(*rec));
                }
                return true;
            };
            if (!ReadRecords(AnCount, m.Answers) || !ReadRecords(NsCount, m.Authority) ||
                !ReadRecords(ArCount, m.Additional))
            {
                return std::nullopt;
            }
            return m;
        }

        /**
         * @brief 创建标准递归查询报文
         * @param domain 待查询域名（自动转小写并去除末尾点号）
         * @param qt 查询类型
         * @return 构造好的查询报文（id=0, rd=true, opcode=0）
         */
        [[nodiscard]] static auto MakeQuery(std::string_view domain, QType qt) -> Message
        {
            Message m;
            m.Id = 0;
            m.Rd = true;
            Question q;
            q.Name = NormalizeName(domain);
            q.QueryType = qt;
            m.Questions.push_back(std::move(q));
            return m;
        }

        /**
         * @brief 规范化域名为小写并去除末尾点号
         * @param domain 原始域名
         * @return 规范化后的域名
         */
        [[nodiscard]] static auto NormalizeName(std::string_view domain) -> std::string
        {
            std::string out(domain);
            while (!out.empty() && out.back() == '.')
            {
                out.pop_back();
            }
            for (auto &ch : out)
            {
                if (ch >= 'A' && ch <= 'Z')
                {
                    ch = static_cast<char>(ch - 'A' + 'a');
                }
            }
            return out;
        }

        /**
         * @brief 提取应答段中所有 A/AAAA 记录的 IP 地址
         * @return 地址列表（A → v4，AAAA → v6，其余类型跳过）
         */
        [[nodiscard]] auto ExtractIps() const -> std::vector<boost::asio::ip::address>
        {
            std::vector<boost::asio::ip::address> ips;
            ips.reserve(Answers.size());
            for (const auto &rec : Answers)
            {
                if (auto v4 = ExtractIpv4(rec))
                {
                    ips.emplace_back(*v4);
                }
                else if (auto v6 = ExtractIpv6(rec))
                {
                    ips.emplace_back(*v6);
                }
            }
            return ips;
        }

        /**
         * @brief 计算三段所有记录中的最小 TTL
         * @return 最小 TTL；无任何记录返回 0
         */
        [[nodiscard]] auto MinTtl() const -> std::uint32_t
        {
            std::uint32_t best = 0;
            bool has = false;
            const auto Scan = [&](const std::vector<Record> &records)
            {
                for (const auto &r : records)
                {
                    if (r.Type == QType::Opt)
                    {
                        continue; // OPT 的 TTL 字段是扩展标志位，非生存时间
                    }
                    best = has ? std::min(best, r.Ttl) : r.Ttl;
                    has = true;
                }
            };
            Scan(Answers);
            Scan(Authority);
            Scan(Additional);
            return best;
        }
    };

    /**
     * @brief 将 DNS 报文封装为 TCP 帧格式（2 字节大端长度前缀）
     * @param msg 待封装报文
     * @return 长度前缀 + 报文字节
     */
    [[nodiscard]] inline auto PackTcp(const Message &msg) -> std::vector<std::uint8_t>
    {
        auto Body = msg.Pack();
        std::vector<std::uint8_t> out;
        out.reserve(Body.size() + 2);
        Detail::PutU16(out, static_cast<std::uint16_t>(Body.size()));
        out.insert(out.end(), Body.begin(), Body.end());
        return out;
    }

    /**
     * @brief 从 TCP 帧解析 DNS 报文
     * @param data 含 2 字节长度前缀的完整帧
     * @return 解析成功返回 Message；前缀声明的长度与实际不符时返回 nullopt
     */
    [[nodiscard]] inline auto UnpackTcp(std::span<const std::uint8_t> data) -> std::optional<Message>
    {
        if (data.size() < 2)
        {
            return std::nullopt;
        }
        const auto Len = static_cast<std::size_t>((data[0] << 8) | data[1]);
        if (data.size() < 2 + Len)
        {
            return std::nullopt;
        }
        return Message::Unpack(data.subspan(2, Len));
    }

} // namespace Preview::Network::Dns
