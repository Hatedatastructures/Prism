/**
 * @file TuicOptions.hpp
 * @brief TUIC 互操作程序的私有命令行选项与端点 API。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Tuic/Tuic.hpp>

namespace Prism::Testing::TuicInterop
{

    struct Options
    {
        std::string Mode{"server"};
        std::string Address{"127.0.0.1:19087"};
        std::string Password{"tuic_password"};
        bool Udp{false};
        std::array<std::uint8_t, 16> Uuid{
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
            0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
    };

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> std::optional<Options>;
    [[nodiscard]] auto SplitHostPort(std::string_view Value) -> std::optional<HostPort>;

    auto CloseAndDrainTuicDgram(const Prism::Tuic::SharedDgram &Datagram)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;
    auto RunServer(Options OptionsValue) -> boost::asio::awaitable<int>;

} // namespace Prism::Testing::TuicInterop
