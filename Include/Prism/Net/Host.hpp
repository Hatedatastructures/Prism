/** @file Host.hpp @brief 固定容量目标主机及显式文本、wire 地址边界。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/DomainName.hpp>
#include <boost/asio/ip/address.hpp>
#include <array>
#include <expected>
#include <optional>
#include <string_view>
#include <utility>
#include <variant>
namespace Prism::Network
{
    struct Ipv4Bytes final { std::array<unsigned char, 4> Bytes{}; auto operator==(const Ipv4Bytes&) const -> bool = default; };
    struct Ipv6Bytes final { std::array<unsigned char, 16> Bytes{}; auto operator==(const Ipv6Bytes&) const -> bool = default; };
    /** @brief 值拥有全部地址；空值只用于无目标的 mux/root，不拥有 I/O 或关闭责任。 */
    class Host final
    {
    public:
        using Value = std::variant<std::monostate, Ipv4Bytes, Ipv6Bytes, DomainName>;
        Host() = default;
        explicit Host(Ipv4Bytes Address) : Value_(Address) {}
        explicit Host(Ipv6Bytes Address) : Value_(Address) {}
        explicit Host(DomainName Domain) : Value_(std::move(Domain)) {}
        [[nodiscard]] auto Empty() const noexcept -> bool { return std::holds_alternative<std::monostate>(Value_); }
        [[nodiscard]] auto Get() const & noexcept -> const Value& { return Value_; }
        auto Get() const && -> const Value& = delete;
        auto operator==(const Host&) const -> bool = default;
    private:
        Value Value_;
    };
    enum class HostEncoding { Domain, Ipv4Text, Ipv6Text, Ipv4Bytes, Ipv6Bytes };
    /** @brief 按 wire 声明的地址族转换一次；不按长度猜测类型，失败返回 InvalidArgument。 */
    [[nodiscard]] auto DecodeHost(HostEncoding Encoding, std::string_view Input) noexcept
        -> std::expected<Host, Prism::Fault::Failure>;
    /** @brief 冷配置文本入口；数值地址通过 error_code 解析，域名按标签规范化。 */
    [[nodiscard]] auto ParseHost(std::string_view Input) noexcept
        -> std::expected<Host, Prism::Fault::Failure>;
    /** @brief 返回无分配的数值地址；域名和空目标返回空，不执行 DNS。 */
    [[nodiscard]] auto IpAddress(const Host& Input) noexcept -> std::optional<boost::asio::ip::address>;
    /** @brief 从已解析数值地址复制字节，不经过字符串；IPv6 scope 不属于本目标契约。 */
    [[nodiscard]] auto FromIpAddress(const boost::asio::ip::address& Address) noexcept
        -> std::expected<Host, Prism::Fault::Failure>;
}
