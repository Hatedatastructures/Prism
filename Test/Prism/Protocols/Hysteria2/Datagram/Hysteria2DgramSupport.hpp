#pragma once

/**
 * @file Hysteria2DgramSupport.hpp
 * @brief Hysteria2 Conn/Dgram 测试共享辅助。
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手 + TCP 数据双向回显
 * 2. Conn UDP 数据面（AsyncSendDatagram / AsyncReceiveDatagram）
 * 3. 错误分支：bad_auth / bad_magic / not_open / unexpected_eof / bad_message
 * 4. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release / lowest_layer
 * 5. Dgram 包连接：发送接收、地址解析、错误分支
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

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Unreliable.hpp>
#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <Prism/Protocols/Quic/DatagramAdapter.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <TestSupport/Prism/Quic/MemoryDatagramProvider.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Prism = ::Prism;
    namespace Hysteria2 = Prism::Hysteria2;

    using Address = Hysteria2::Address;
    using AddressType = Hysteria2::AddressType;
    using ClientConfig = Hysteria2::ClientConfig;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;
    using Conn = Hysteria2::Conn<>;
    using DatagramAdapter = Prism::Quic::DatagramAdapter;
    using Dgram = Hysteria2::Dgram<>;
    using Error = Prism::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryDatagramProvider = Prism::Testing::MemoryDatagramProvider;
    using MemoryStream = Prism::MemoryStream;
    using Message = Hysteria2::Message;
    using PrismMockTransport = Prism::PrismMockTransport;
    using ServerConfig = Hysteria2::ServerConfig;
    using Unreliable = Prism::Transport::Unreliable;

    using Prism::AsBytes;
    using Prism::AsU8Span;
    using Prism::MakeMemoryPair;

    /// 运行协程直至完成（异常重抛）
    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &IoContext, Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto CompletionHandler =
            [&Exception, &IoContext](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            std::move(CompletionHandler));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /// 立即启动并观察服务端协程，避免异常或未完成操作被静默丢弃。
    [[nodiscard]] auto SpawnServer(
        ExecutorType Executor,
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

    /// 构造 hysteria2 目标地址
    [[nodiscard]] auto MakeAddress(
        const AddressType Type,
        std::string Host,
        const std::uint16_t Port) -> Address
    {
        Address AddressValue{};
        AddressValue.Type = Type;
        AddressValue.Host = std::move(Host);
        AddressValue.Port = Port;
        return AddressValue;
    }

    /** @brief Dgram 接收兼容帧的真实字段值对象。 */
    struct ReceiveWireRequest final
    {
        std::uint8_t Atyp;
        std::vector<std::uint8_t> AddressBytes;
        std::uint16_t Port;
        std::string Payload;
    };

    /**
     * @brief 构造 Dgram 接收侧兼容帧。
     * @details 保持 9 字节 Kind/Session/PacketId 头、独立 ATYP、地址、端口和 payload 顺序。
     * @param Request 接收帧字段。
     * @return 可直接写入测试传输的完整 wire。
     */
    [[nodiscard]] inline auto BuildReceiveWire(const ReceiveWireRequest &Request)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire(9, 0);
        Wire[0] = 0x02;
        Wire.push_back(Request.Atyp);
        Wire.insert(Wire.end(), Request.AddressBytes.begin(), Request.AddressBytes.end());
        Wire.push_back(static_cast<std::uint8_t>(Request.Port >> 8));
        Wire.push_back(static_cast<std::uint8_t>(Request.Port & 0xFF));
        Wire.insert(Wire.end(), Request.Payload.begin(), Request.Payload.end());
        return Wire;
    }

} // namespace
