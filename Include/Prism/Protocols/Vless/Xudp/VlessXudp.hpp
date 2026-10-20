/**
 * @file VlessXudp.hpp
 * @brief VLESS XUDP（CommandMux）数据面解析与 UDP relay
 * @details 对齐 metacubex/sing-vmess v0.2.5 `xudp.go` / `mux.go` 的真实 wire：
 *          - 帧头 [2B Length][2B SessionId][1B Status][1B Option]
 *          - Length = 4 + body；body = [Network 1B][port-first AddrPort][globalID?]
 *          - payload 长度位于 body 之后，独立 2B 大端
 *          - 地址族：IPv4=0x01 / Fqdn=0x02 / IPv6=0x03；端口先于地址族字节
 *          - New 帧携带目标；Keep 短帧（Length=4）沿用会话已存目标
 *          - OptionError 表示远端关闭；OptionData 未置位表示空载荷控制帧
 * @note 回包帧使用长格式（network + 源地址），与 sing 服务端 writePacketFrame 对齐。
 */

#pragma once
#include <Prism/Net/Target.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>

#include <Prism/Transport/Transmission.hpp>

namespace Prism::Vless::Xudp
{

    namespace Net = boost::asio;

    /// XUDP 帧状态（对齐 sing-vmess Status* 常量）
    enum class Status : std::uint8_t
    {
        New = 1,
        Keep = 2,
        End = 3,
        KeepAlive = 4,
    };

    /// 帧选项位（对齐 sing-vmess Option* 常量）
    inline constexpr std::uint8_t OptionData = 0x01U;
    inline constexpr std::uint8_t OptionError = 0x02U;
    /// XUDP 网络类型：UDP（对齐 sing-vmess NetworkUDP）
    inline constexpr std::uint8_t NetworkUdp = 0x02U;
    /// 地址族（对齐 sing-vmess AddressSerializer 映射）
    inline constexpr std::uint8_t FamilyIpv4 = 0x01U;
    inline constexpr std::uint8_t FamilyFqdn = 0x02U;
    inline constexpr std::uint8_t FamilyIpv6 = 0x03U;
    /// 单包最大载荷（UDP 上限）
    inline constexpr std::size_t MaxDatagram = 65535U;
    /// 上游回包等待上限（避免静默上游长期占用会话）
    inline constexpr auto ResponseTimeout = std::chrono::seconds(5);

    /**
     * @struct Frame
     * @brief 解析后的 XUDP 帧
     */
    struct Frame final
    {
        std::uint16_t SessionId{0};
        Status StatusValue{Status::Keep};
        bool HasTarget{false};
        Prism::Network::Target Target;
        std::vector<std::uint8_t> Payload;
    };

    /** @brief 拥有型地址解析结果及实际消费长度。 */
    struct Address final { Prism::Network::Target Target; std::size_t Consumed{0}; };
    /**
     * @brief 解析 port-first 地址（[Port 2B BE][Family 1B][Addr body]）。
     * @param Data 借用的地址 wire。
     * @return 拥有的目标与准确 Consumed；不足或非法返回空，不执行 I/O。
     * @note 地址之后允许保留 globalID 等尾随字节。
     */
    [[nodiscard]] auto ReadAddress(std::span<const std::uint8_t> Data) -> std::optional<Address>;

    /** @brief 从入站传输精确读取并校验一条 XUDP 帧。 */
    [[nodiscard]] auto ReadFrame(Prism::SharedTransmission Inbound)
        -> Net::awaitable<std::expected<Frame, Prism::Fault::Failure>>;

    /** @brief 一条完整回包的 owning wire 请求，编码不执行 I/O。 */
    struct Reply final
    {
        std::uint16_t SessionId;
        Net::ip::udp::endpoint Source;
        std::vector<std::uint8_t> Payload;
    };
    /** @brief 编码一条 XUDP UDP 回包 wire，不执行 I/O。 */
    [[nodiscard]] auto EncodeReply(Reply Value) -> std::vector<std::byte>;
    /** @brief 编码指定会话的 XUDP End 控制帧。 */
    [[nodiscard]] auto EncodeEnd(std::uint16_t Id) -> std::vector<std::byte>;
}
