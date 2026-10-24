/** @file NetworkValues.cpp @brief 网络目标值模型的解析、地址转换与显示格式实现。 */
#include <Prism/Net/DomainName.hpp>
#include <Prism/Net/Host.hpp>
#include <Prism/Net/HostText.hpp>
#include <Prism/Net/Target.hpp>

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>

namespace Prism::Network
{
    auto DomainName::Parse(std::string_view Text) noexcept
        -> std::expected<DomainName, Prism::Fault::Failure>
    {
        if (Text.ends_with('.')) Text.remove_suffix(1);
        if (Text.empty() || Text.size() > Capacity)
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
        DomainName Result;
        std::size_t Label = 0;
        char Previous = 0;
        for (char Character : Text)
        {
            if (Character >= 'A' && Character <= 'Z') Character += 'a' - 'A';
            if (Character == '.')
            {
                if (Label == 0 || Previous == '-')
                    return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
                Label = 0;
            }
            else
            {
                const bool Letter = Character >= 'a' && Character <= 'z';
                const bool Digit = Character >= '0' && Character <= '9';
                if ((!Letter && !Digit && Character != '-') ||
                    (Label == 0 && Character == '-') || ++Label > 63)
                    return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
            }
            Result.Bytes_[Result.Size_++] = Character;
            Previous = Character;
        }
        if (Label == 0 || Previous == '-')
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
        return Result;
    }

    auto DecodeHost(HostEncoding Encoding, std::string_view Input) noexcept
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

    auto ParseHost(std::string_view Input) noexcept
        -> std::expected<Host, Prism::Fault::Failure>
    {
        if (Input.find(':') != std::string_view::npos) return DecodeHost(HostEncoding::Ipv6Text, Input);
        auto Ipv4 = DecodeHost(HostEncoding::Ipv4Text, Input);
        if (Ipv4) return Ipv4;
        return DecodeHost(HostEncoding::Domain, Input);
    }

    auto IpAddress(const Host& Input) noexcept -> std::optional<boost::asio::ip::address>
    {
        if (const auto* V4 = std::get_if<Ipv4Bytes>(&Input.Get())) return boost::asio::ip::address_v4(V4->Bytes);
        if (const auto* V6 = std::get_if<Ipv6Bytes>(&Input.Get())) return boost::asio::ip::address_v6(V6->Bytes);
        return std::nullopt;
    }

    auto FromIpAddress(const boost::asio::ip::address& Address) noexcept
        -> std::expected<Host, Prism::Fault::Failure>
    {
        if (Address.is_v4()) return Host(Ipv4Bytes{Address.to_v4().to_bytes()});
        if (Address.to_v6().scope_id() != 0)
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
        return Host(Ipv6Bytes{Address.to_v6().to_bytes()});
    }

    auto ToText(const Host& Input) noexcept -> HostText
    {
        HostText Result;
        auto* Cursor = Result.Bytes_.data();
        auto* End = Cursor + Result.Bytes_.size();
        if (const auto* Domain = std::get_if<DomainName>(&Input.Get()))
            Cursor = std::copy(Domain->View().begin(), Domain->View().end(), Cursor);
        else if (const auto* V4 = std::get_if<Ipv4Bytes>(&Input.Get()))
        {
            for (std::size_t Index = 0; Index < 4; ++Index)
            {
                if (Index != 0) *Cursor++ = '.';
                Cursor = std::to_chars(Cursor, End, V4->Bytes[Index]).ptr;
            }
        }
        else if (const auto* V6 = std::get_if<Ipv6Bytes>(&Input.Get()))
        {
            for (std::size_t Index = 0; Index < 16; Index += 2)
            {
                if (Index != 0) *Cursor++ = ':';
                const auto Word = static_cast<unsigned>(V6->Bytes[Index]) * 256U + V6->Bytes[Index + 1];
                Cursor = std::to_chars(Cursor, End, Word, 16).ptr;
            }
        }
        Result.Size_ = static_cast<std::size_t>(Cursor - Result.Bytes_.data());
        return Result;
    }

    auto ParsePort(std::string_view Text) noexcept
        -> std::expected<std::uint16_t, Prism::Fault::Failure>
    {
        if (Text.empty())
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
        std::uint32_t Port = 0;
        const auto [End, Error] = std::from_chars(Text.data(), Text.data() + Text.size(), Port);
        if (Error != std::errc{} || End != Text.data() + Text.size() || Port == 0 || Port > 65535)
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument, {}});
        return static_cast<std::uint16_t>(Port);
    }
}
