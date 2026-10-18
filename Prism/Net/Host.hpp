/** @file Host.hpp @brief 固定容量目标主机及显式文本、wire 地址边界。 */
#pragma once
#include <Prism/Net/DomainName.hpp>
#include <boost/asio/ip/address.hpp>
#include <algorithm>
#include <optional>
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
    [[nodiscard]] inline auto DecodeHost(HostEncoding Encoding, std::string_view Input) noexcept
        -> std::expected<Host, Prism::Fault::Failure>
    {
        if (Encoding == HostEncoding::Domain)
        {
            auto Domain = DomainName::Parse(Input);
            if (!Domain) return std::unexpected(Domain.error());
            return Host(std::move(*Domain));
        }
        if (Encoding == HostEncoding::Ipv4Bytes)
        {
            if (Input.size() != 4) return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
            Ipv4Bytes Bytes;
            std::copy(Input.begin(), Input.end(), Bytes.Bytes.begin());
            return Host(Bytes);
        }
        if (Encoding == HostEncoding::Ipv6Bytes)
        {
            if (Input.size() != 16) return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
            Ipv6Bytes Bytes;
            std::copy(Input.begin(), Input.end(), Bytes.Bytes.begin());
            return Host(Bytes);
        }
        if (Input.empty() || Input.size() > 45 || Input.find('\0') != std::string_view::npos ||
            Input.find('%') != std::string_view::npos)
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
        std::array<char, 46> Text{};
        std::copy(Input.begin(), Input.end(), Text.begin());
        boost::system::error_code Error;
        if (Encoding == HostEncoding::Ipv4Text)
        {
            const auto Address = boost::asio::ip::make_address_v4(Text.data(), Error);
            if (!Error) return Host(Ipv4Bytes{Address.to_bytes()});
        }
        else if (Encoding == HostEncoding::Ipv6Text)
        {
            const auto Address = boost::asio::ip::make_address_v6(Text.data(), Error);
            if (!Error) return Host(Ipv6Bytes{Address.to_bytes()});
        }
        return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, Error});
    }
    /** @brief 冷配置文本入口；数值地址通过 error_code 解析，域名按标签规范化。 */
    [[nodiscard]] inline auto ParseHost(std::string_view Input) noexcept
        -> std::expected<Host, Prism::Fault::Failure>
    {
        if (Input.find(':') != std::string_view::npos) return DecodeHost(HostEncoding::Ipv6Text, Input);
        auto Ipv4 = DecodeHost(HostEncoding::Ipv4Text, Input);
        if (Ipv4) return Ipv4;
        return DecodeHost(HostEncoding::Domain, Input);
    }
    /** @brief 返回无分配的数值地址；域名和空目标返回空，不执行 DNS。 */
    [[nodiscard]] inline auto IpAddress(const Host& Input) noexcept -> std::optional<boost::asio::ip::address>
    {
        if (const auto* V4 = std::get_if<Ipv4Bytes>(&Input.Get())) return boost::asio::ip::address_v4(V4->Bytes);
        if (const auto* V6 = std::get_if<Ipv6Bytes>(&Input.Get())) return boost::asio::ip::address_v6(V6->Bytes);
        return std::nullopt;
    }
    /** @brief 从已解析数值地址复制字节，不经过字符串；IPv6 scope 不属于本目标契约。 */
    [[nodiscard]] inline auto FromIpAddress(const boost::asio::ip::address& Address) noexcept
        -> std::expected<Host, Prism::Fault::Failure>
    {
        if (Address.is_v4()) return Host(Ipv4Bytes{Address.to_v4().to_bytes()});
        if (Address.to_v6().scope_id() != 0)
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
        return Host(Ipv6Bytes{Address.to_v6().to_bytes()});
    }
}
