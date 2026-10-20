/**
 * @file Format.hpp
 * @brief DNS 报文编解码的公共值类型与接口。
 * @details DNS 二进制报文的构造与解析实现位于 Net/Dns owner 编译单元。
 */
#pragma once

#include <Prism/Net/Dns/QueryType.hpp>
#include <Prism/Net/DomainName.hpp>

#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Prism::Network::Dns
{
    /** @brief DNS 查询段。 */
    struct Question
    {
        std::string Name;        ///< 域名，小写无末尾点号。
        QType QueryType{};       ///< 查询类型。
        std::uint16_t QClass{1}; ///< 查询类，默认 IN（Internet）。
    };

    /** @brief DNS 资源记录；RDATA 保留原始 wire 字节。 */
    struct Record
    {
        std::string Name;               ///< 拥有者名称，小写无末尾点号。
        QType Type{};                   ///< 记录类型。
        std::uint16_t RClass{1};        ///< 记录类，默认 IN。
        std::uint32_t Ttl{0};           ///< 生存时间（秒）。
        std::vector<std::uint8_t> Rdata; ///< 原始 RDATA 字节。
    };

    /** @brief 从 A 记录提取 IPv4 地址；长度不是 4 字节时返回空值。 */
    [[nodiscard]] auto ExtractIpv4(const Record &RecordValue)
        -> std::optional<boost::asio::ip::address_v4>;

    /** @brief 从 AAAA 记录提取 IPv6 地址；长度不是 16 字节时返回空值。 */
    [[nodiscard]] auto ExtractIpv6(const Record &RecordValue)
        -> std::optional<boost::asio::ip::address_v6>;

    /**
     * @brief DNS 报文值类型。
     * @details 字段由调用方拥有；编码和解码通过 Net/Dns owner 编译单元执行。
     */
    class Message
    {
    public:
        std::uint16_t Id{0};    ///< 报文标识。
        bool Qr{false};         ///< 0=查询，1=响应。
        std::uint8_t Opcode{0}; ///< 操作码（0=标准查询）。
        bool Aa{false};         ///< 权威应答。
        bool Tc{false};         ///< 截断标志。
        bool Rd{false};         ///< 期望递归。
        bool Ra{false};         ///< 可用递归。
        std::uint8_t Rcode{0};  ///< 响应码（0=NOERROR，3=NXDOMAIN）。

        std::vector<Question> Questions; ///< 查询段。
        std::vector<Record> Answers;      ///< 应答段。
        std::vector<Record> Authority;    ///< 权威段。
        std::vector<Record> Additional;   ///< 附加段。

        /** @brief 序列化为含域名压缩的 DNS wire format。 */
        [[nodiscard]] auto Pack() const -> std::vector<std::uint8_t>;

        /** @brief 解析完整 DNS wire 报文；畸形输入返回空值。 */
        [[nodiscard]] static auto Unpack(std::span<const std::uint8_t> Data)
            -> std::optional<Message>;

        /** @brief 创建 id=0、RD=1 的标准递归查询报文。 */
        [[nodiscard]] static auto MakeQuery(const DomainName &Domain, QType QueryType)
            -> Message;

        /** @brief 域名转换为小写并移除末尾点号。 */
        [[nodiscard]] static auto NormalizeName(std::string_view Domain) -> std::string;
    };

    /** @brief 将 DNS 报文封装为 2 字节大端长度前缀的 TCP 帧。 */
    [[nodiscard]] auto PackTcp(const Message &MessageValue) -> std::vector<std::uint8_t>;

    /** @brief 从 TCP 帧解析一条 DNS 报文；长度不足时返回空值。 */
    [[nodiscard]] auto UnpackTcp(std::span<const std::uint8_t> Data)
        -> std::optional<Message>;
} // namespace Prism::Network::Dns
