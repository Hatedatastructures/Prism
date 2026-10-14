#pragma once

/**
 * @file VlessConnSessionSupport.hpp
 * @brief VLESS Conn/Dgram 测试共享辅助。
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（域名 + 预读缓冲路径）+ 双向回显
 * 2. UDP 数据面：ConnectPacket / AcceptPacket + Dgram 收发往返
 * 3. 错误分支：bad_magic / bad_message / bad_auth / not_supported / io_error
 * 4. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
 * @note 仅提供两个测试 CPP 共同使用的协议 fixture，不承载 TEST 宏。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Contract/Ingress/StreamFactory.hpp>
#include <Preview/Protocols/Vless/IngressFactory.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{
    namespace Preview = ::Preview;
    namespace Net = boost::asio;
    namespace Vless = Preview::Vless;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::PreviewMockTransport;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto RunCoro(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto CompletionHandler = [&Exception, &IoContext](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Coroutine), std::move(CompletionHandler));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    [[nodiscard]] auto SpawnServer(
        Net::any_io_executor Executor,
        Net::awaitable<void> Coroutine)
        -> std::shared_ptr<CompletionChannel>
    {
        const auto Done =
            std::make_shared<CompletionChannel>(Executor, 1);
        auto CompletionHandler =
            [Done](std::exception_ptr Exception) -> void
        {
            (void)Done->try_send(
                boost::system::error_code{},
                Exception == nullptr);
        };
        Net::co_spawn(
            Executor,
            std::move(Coroutine),
            std::move(CompletionHandler));
        return Done;
    }

    /// 测试 UUID（固定值，两字节交替模式便于识别）
    auto TestUuid() -> std::array<std::uint8_t, Vless::UuidLen>
    {
        std::array<std::uint8_t, Vless::UuidLen> Uuid{};
        for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
        {
            Uuid[Index] = static_cast<std::uint8_t>(0x10 + Index);
        }
        return Uuid;
    }

    /// 构造 vless 目标地址
    auto MakeAddress(Vless::AddressType Type, std::string Host, std::uint16_t Port) -> Vless::Address
    {
        Vless::Address Address{};
        Address.Type = Type;
        Address.Host = std::move(Host);
        Address.Port = Port;
        return Address;
    }

    /// 原始客户端：构造请求头字节
    auto BuildRawRequest(const std::array<std::uint8_t, Vless::UuidLen> &Uuid, Vless::Command Command,
                         const Vless::Address &Target) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire;
        Wire.push_back(Vless::ProtocolVersion);
        Wire.insert(Wire.end(), Uuid.begin(), Uuid.end());
        Wire.push_back(0x00); // addnl len
        Wire.push_back(static_cast<std::uint8_t>(Command));
        if (Command == Vless::Command::Mux)
        {
            return Wire;
        }
        Wire.push_back(static_cast<std::uint8_t>(Target.Port >> 8));
        Wire.push_back(static_cast<std::uint8_t>(Target.Port & 0xFF));
        Wire.push_back(static_cast<std::uint8_t>(Target.Type));
        switch (Target.Type)
        {
        case Vless::AddressType::Ipv4: {
            std::uint32_t Octet = 0;
            for (const char Character : Target.Host)
            {
                if (Character == '.')
                {
                    Wire.push_back(static_cast<std::uint8_t>(Octet));
                    Octet = 0;
                }
                else
                {
                    Octet = Octet * 10 + static_cast<std::uint32_t>(Character - '0');
                }
            }
            Wire.push_back(static_cast<std::uint8_t>(Octet));
            break;
        }
        case Vless::AddressType::Ipv6:
            Wire.insert(Wire.end(), Target.Host.begin(), Target.Host.end());
            break;
        case Vless::AddressType::Domain:
        default:
            Wire.push_back(static_cast<std::uint8_t>(Target.Host.size()));
            Wire.insert(Wire.end(), Target.Host.begin(), Target.Host.end());
            break;
        }
        return Wire;
    }

} // namespace

