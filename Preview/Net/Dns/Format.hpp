/**
 * @file Format.hpp
 * @brief DNS 报文编解码层（RFC 1035）
 * @details DNS 二进制报文的构造与解析，完全不依赖系统 resolver，对齐主项目
 *          net/dns/detail/format.hpp 分层。支持：
 *          - 域名压缩指针编码与解码（跳转循环检测）
 *          - Header / Question / Answer / Authority / Additional 全段编解码
 *          - A/AAAA/CNAME/NS/MX/TXT/SOA/OPT 记录类型
 *          - TCP 2 字节长度前缀帧封装（PackTcp / UnpackTcp）
 * @note rdata 保持原始字节（不做 rdata 内部域名压缩），A/AAAA 的 rdata 为
 *       裸 4/16 字节地址，与主项目行为一致
 */

#pragma once

#include <Preview/Net/Dns/Detail/Name.hpp>
#include <Preview/Net/Dns/Detail/Record.hpp>
#include <Preview/Net/Dns/QueryType.hpp>
#include <Preview/Net/DomainName.hpp>

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
     * @param RecordValue DNS 资源记录
     * @return rdata 恰好 4 字节时返回对应地址，否则 nullopt
     */
    [[nodiscard]] inline auto ExtractIpv4(const Record &RecordValue) -> std::optional<boost::asio::ip::address_v4>
    {
        if (RecordValue.Type != QType::A || RecordValue.Rdata.size() != 4)
        {
            return std::nullopt;
        }
        const auto Raw = static_cast<std::uint32_t>(RecordValue.Rdata[0]) << 24 |
                         static_cast<std::uint32_t>(RecordValue.Rdata[1]) << 16 |
                         static_cast<std::uint32_t>(RecordValue.Rdata[2]) << 8 |
                         static_cast<std::uint32_t>(RecordValue.Rdata[3]);
        return boost::asio::ip::address_v4(Raw);
    }

    /**
     * @brief 从 AAAA 记录提取 IPv6 地址
     * @param RecordValue DNS 资源记录
     * @return rdata 恰好 16 字节时返回对应地址，否则 nullopt
     */
    [[nodiscard]] inline auto ExtractIpv6(const Record &RecordValue) -> std::optional<boost::asio::ip::address_v6>
    {
        if (RecordValue.Type != QType::Aaaa || RecordValue.Rdata.size() != 16)
        {
            return std::nullopt;
        }
        std::array<unsigned char, 16> Bytes{};
        std::memcpy(Bytes.data(), RecordValue.Rdata.data(), Bytes.size());
        return boost::asio::ip::address_v6(Bytes);
    }

    namespace Detail
    {
        /// 大端写入 16 位整数
        inline auto PutU16(std::vector<std::uint8_t> &Output, const std::uint16_t Value) -> void
        {
            Output.push_back(static_cast<std::uint8_t>(Value >> 8));
            Output.push_back(static_cast<std::uint8_t>(Value & 0xFF));
        }

        /// 大端写入 32 位整数
        inline auto PutU32(std::vector<std::uint8_t> &Output, const std::uint32_t Value) -> void
        {
            Output.push_back(static_cast<std::uint8_t>(Value >> 24));
            Output.push_back(static_cast<std::uint8_t>((Value >> 16) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>(Value & 0xFF));
        }

        /**
         * @brief 编码域名字节序列（带压缩指针）
         * @details 从完整域名开始逐级后缀查压缩表：命中则写 2 字节指针
         *          （0xC000 | offset）并结束；未命中写 "长度+标签" 并把当前
         *          后缀登记进压缩表（offset 必须落在 14 位可表示范围内）。
         * @param Output 输出字节流
         * @param Name 小写无末尾点号域名
         * @param Compression 压缩表（后缀 → 报文内偏移）
         */
        inline auto AppendName(std::vector<std::uint8_t> &Output, std::string_view Name,
                               std::unordered_map<std::string, std::uint16_t> &Compression) -> void
        {
            while (!Name.empty())
            {
                if (const auto It = Compression.find(std::string(Name)); It != Compression.end())
                {
                    const auto Ptr = static_cast<std::uint16_t>(0xC000u | It->second);
                    PutU16(Output, Ptr);
                    return;
                }
                if (Output.size() <= 0x3FFF)
                {
                    Compression.emplace(std::string(Name), static_cast<std::uint16_t>(Output.size()));
                }
                const auto Dot = Name.find('.');
                std::string_view Label = Name;
                if (Dot != std::string_view::npos)
                {
                    Label = Name.substr(0, Dot);
                }
                if (Label.empty() || Label.size() > 63)
                {
                    return; // 非法标签：丢弃尾部（调用方应保证输入已规范化）
                }
                Output.push_back(static_cast<std::uint8_t>(Label.size()));
                Output.insert(Output.end(), Label.begin(), Label.end());
                if (Dot == std::string_view::npos)
                {
                    break;
                }
                Name = Name.substr(Dot + 1);
            }
            Output.push_back(0);
        }

        /**
         * @brief 从报文解码域名（处理压缩指针）
         * @param Data 完整报文
         * @param Offset 输入输出 解码起始偏移；成功后推进到名字之后的第一个字节
         * @return 小写无末尾点号域名；畸形输入（越界/循环/超长）返回 nullopt
         */
        [[nodiscard]] inline auto DecodeName(std::span<const std::uint8_t> Data, std::size_t &Offset)
            -> std::optional<std::string>
        {
            NameCursor Cursor{Data, Offset};
            const auto Name = ReadName(Cursor);
            if (!Name)
            {
                return std::nullopt;
            }
            Offset = Cursor.Offset;
            return std::string(Name->View());
        }

        /// 编码单条资源记录（Name 参与压缩，rdata 原样写入）
        inline auto AppendRecord(std::vector<std::uint8_t> &Output, const Record &RecordValue,
                                 std::unordered_map<std::string, std::uint16_t> &Compression) -> void
        {
            AppendName(Output, RecordValue.Name, Compression);
            PutU16(Output, static_cast<std::uint16_t>(RecordValue.Type));
            PutU16(Output, RecordValue.RClass);
            PutU32(Output, RecordValue.Ttl);
            PutU16(Output, static_cast<std::uint16_t>(RecordValue.Rdata.size()));
            Output.insert(Output.end(), RecordValue.Rdata.begin(), RecordValue.Rdata.end());
        }

        /// 从报文解码单条资源记录
        [[nodiscard]] inline auto DecodeRecord(std::span<const std::uint8_t> Data, std::size_t &Offset)
            -> std::optional<Record>
        {
            NameCursor Cursor{Data, Offset};
            const auto Parsed = ReadRecord(Cursor);
            if (!Parsed) return std::nullopt;
            Record RecordValue;
            RecordValue.Name = Parsed->Name.View();
            RecordValue.Type = static_cast<QType>(Parsed->Type);
            RecordValue.RClass = Parsed->Class;
            RecordValue.Ttl = Parsed->Ttl;
            RecordValue.Rdata.assign(Parsed->Rdata.begin(), Parsed->Rdata.end());
            Offset = Cursor.Offset;
            return RecordValue;
        }

        /**
         * @brief 从一个 DNS 段读取指定数量的完整记录。
         * @param Cursor 当前报文游标。
         * @param Count 本段记录数量。
         * @param Records 接收记录的拥有容器。
         * @return 全部记录完整时返回 true，否则保留调用方已有结果并返回 false。
         */
        [[nodiscard]] inline auto ReadRecords(NameCursor &Cursor,
                                               const std::uint16_t Count,
                                               std::vector<Record> &Records) -> bool
        {
            for (std::uint16_t Index = 0; Index < Count; ++Index)
            {
                auto RecordValue = DecodeRecord(Cursor.Data, Cursor.Offset);
                if (!RecordValue)
                {
                    return false;
                }
                Records.push_back(std::move(*RecordValue));
            }
            return true;
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
            std::vector<std::uint8_t> Output;
            Output.reserve(512);
            Detail::PutU16(Output, Id);

            std::uint16_t Flags = static_cast<std::uint16_t>((Opcode & 0x0Fu) << 11) |
                                  static_cast<std::uint16_t>(Rcode & 0x0Fu);
            if (Qr)
            {
                Flags = static_cast<std::uint16_t>(Flags | 0x8000u);
            }
            if (Aa)
            {
                Flags = static_cast<std::uint16_t>(Flags | 0x0400u);
            }
            if (Tc)
            {
                Flags = static_cast<std::uint16_t>(Flags | 0x0200u);
            }
            if (Rd)
            {
                Flags = static_cast<std::uint16_t>(Flags | 0x0100u);
            }
            if (Ra)
            {
                Flags = static_cast<std::uint16_t>(Flags | 0x0080u);
            }
            Detail::PutU16(Output, Flags);
            Detail::PutU16(Output, static_cast<std::uint16_t>(Questions.size()));
            Detail::PutU16(Output, static_cast<std::uint16_t>(Answers.size()));
            Detail::PutU16(Output, static_cast<std::uint16_t>(Authority.size()));
            Detail::PutU16(Output, static_cast<std::uint16_t>(Additional.size()));

            std::unordered_map<std::string, std::uint16_t> Compression;
            for (const auto &QuestionValue : Questions)
            {
                Detail::AppendName(Output, QuestionValue.Name, Compression);
                Detail::PutU16(Output, static_cast<std::uint16_t>(QuestionValue.QueryType));
                Detail::PutU16(Output, QuestionValue.QClass);
            }
            for (const auto &RecordValue : Answers)
            {
                Detail::AppendRecord(Output, RecordValue, Compression);
            }
            for (const auto &RecordValue : Authority)
            {
                Detail::AppendRecord(Output, RecordValue, Compression);
            }
            for (const auto &RecordValue : Additional)
            {
                Detail::AppendRecord(Output, RecordValue, Compression);
            }
            return Output;
        }

        /**
         * @brief 从二进制数据反序列化 DNS 报文
         * @param Data 报文字节缓冲区
         * @return 解析成功返回 Message；长度不足/字段越界/压缩指针循环返回 nullopt
         */
        [[nodiscard]] static auto Unpack(std::span<const std::uint8_t> Data) -> std::optional<Message>
        {
            const auto Header = Detail::ReadHeader(Data);
            if (!Header)
            {
                return std::nullopt;
            }
            Message MessageValue;
            MessageValue.Id = Header->Id;
            const auto Flags = Header->Flags;
            MessageValue.Qr = (Flags & 0x8000u) != 0;
            MessageValue.Opcode = static_cast<std::uint8_t>((Flags >> 11) & 0x0Fu);
            MessageValue.Aa = (Flags & 0x0400u) != 0;
            MessageValue.Tc = (Flags & 0x0200u) != 0;
            MessageValue.Rd = (Flags & 0x0100u) != 0;
            MessageValue.Ra = (Flags & 0x0080u) != 0;
            MessageValue.Rcode = static_cast<std::uint8_t>(Flags & 0x0Fu);

            Detail::NameCursor Cursor{Data, 12};
            for (std::uint16_t Index = 0; Index < Header->Questions; ++Index)
            {
                const auto Parsed = Detail::ReadQuestion(Cursor);
                if (!Parsed)
                {
                    return std::nullopt;
                }
                Question QuestionValue;
                QuestionValue.Name = Parsed->Name.View();
                QuestionValue.QueryType = static_cast<QType>(Parsed->Type);
                QuestionValue.QClass = Parsed->Class;
                MessageValue.Questions.push_back(std::move(QuestionValue));
            }
            if (!Detail::ReadRecords(Cursor, Header->Answers, MessageValue.Answers) ||
                !Detail::ReadRecords(Cursor, Header->Authority, MessageValue.Authority) ||
                !Detail::ReadRecords(Cursor, Header->Additional, MessageValue.Additional))
            {
                return std::nullopt;
            }
            return MessageValue;
        }

        /**
         * @brief 创建标准递归查询报文
         * @param Domain 已校验并拥有的规范化域名。
         * @param QueryType 查询类型
         * @return 离线物化报文（id=0, rd=true, opcode=0），生产 query 使用 QueryIdentity::Encode。
         */
        [[nodiscard]] static auto MakeQuery(const DomainName &Domain, QType QueryType) -> Message
        {
            Message MessageValue;
            MessageValue.Id = 0;
            MessageValue.Rd = true;
            Question QuestionValue;
            QuestionValue.Name = Domain.View();
            QuestionValue.QueryType = QueryType;
            MessageValue.Questions.push_back(std::move(QuestionValue));
            return MessageValue;
        }

        /**
         * @brief 规范化域名为小写并去除末尾点号
         * @param Domain 原始域名
         * @return 规范化后的域名
         */
        [[nodiscard]] static auto NormalizeName(std::string_view Domain) -> std::string
        {
            std::string Output(Domain);
            while (!Output.empty() && Output.back() == '.')
            {
                Output.pop_back();
            }
            for (auto &Character : Output)
            {
                if (Character >= 'A' && Character <= 'Z')
                {
                    Character = static_cast<char>(Character - 'A' + 'a');
                }
            }
            return Output;
        }

    };

    /**
     * @brief 将 DNS 报文封装为 TCP 帧格式（2 字节大端长度前缀）
     * @param MessageValue 待封装报文
     * @return 长度前缀 + 报文字节
     */
    [[nodiscard]] inline auto PackTcp(const Message &MessageValue) -> std::vector<std::uint8_t>
    {
        auto Body = MessageValue.Pack();
        std::vector<std::uint8_t> Output;
        Output.reserve(Body.size() + 2);
        Detail::PutU16(Output, static_cast<std::uint16_t>(Body.size()));
        Output.insert(Output.end(), Body.begin(), Body.end());
        return Output;
    }

    /**
     * @brief 从 TCP 帧解析 DNS 报文
     * @param Data 含 2 字节长度前缀的完整帧
     * @return 解析成功返回 Message；前缀声明的长度与实际不符时返回 nullopt
     */
    [[nodiscard]] inline auto UnpackTcp(std::span<const std::uint8_t> Data) -> std::optional<Message>
    {
        if (Data.size() < 2)
        {
            return std::nullopt;
        }
        const auto Len = static_cast<std::size_t>((Data[0] << 8) | Data[1]);
        if (Data.size() < 2 + Len)
        {
            return std::nullopt;
        }
        return Message::Unpack(Data.subspan(2, Len));
    }

} // namespace Preview::Network::Dns
