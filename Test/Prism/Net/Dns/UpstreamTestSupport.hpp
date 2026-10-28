/**
 * @file UpstreamTestSupport.hpp
 * @brief DNS 上游行为测试共享的报文应答与回环服务器夹具。
 */
#pragma once

#include <Prism/Net/Dns/Format.hpp>
#include <Prism/Net/Dns/Upstream.hpp>
#include "ServerTestSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <system_error>

#include <gtest/gtest.h>

namespace
{
    using Prism::Network::Dns::Message;
    using Prism::Network::Dns::QType;
    using Prism::Network::Dns::QueryResult;
    using Prism::Network::Dns::Server;
    using Prism::Network::Dns::Upstream;
    using Prism::Network::Dns::UpstreamOptions;

    using Net::ip::tcp;
    using Net::ip::udp;

    /** @brief 按网络字节序追加 16 位整数。 */
    auto PutU16(std::vector<std::uint8_t> &Output, const std::uint16_t Value) -> void
    {
        Output.push_back(static_cast<std::uint8_t>(Value >> 8));
        Output.push_back(static_cast<std::uint8_t>(Value & 0xFF));
    }

    /** @brief 复制完整 DNS 查询问题段并构造 QR=1 的合法 NOERROR/NODATA 应答。 */
    [[nodiscard]] auto BuildDnsNoDataResponse(const std::span<const std::uint8_t> Query)
        -> std::vector<std::uint8_t>
    {
        if (Query.size() < 12 || Query[4] != 0 || Query[5] != 1)
        {
            return {};
        }
        std::size_t Offset = 12;
        bool NameEnded = false;
        while (Offset < Query.size())
        {
            const auto LabelBytes = Query[Offset++];
            if (LabelBytes == 0)
            {
                NameEnded = true;
                break;
            }
            if (LabelBytes > 63 || LabelBytes > Query.size() - Offset)
            {
                return {};
            }
            Offset += LabelBytes;
        }
        if (!NameEnded || Query.size() - Offset < 4)
        {
            return {};
        }
        std::vector<std::uint8_t> Response;
        Response.reserve(Offset + 4);
        PutU16(Response, static_cast<std::uint16_t>((Query[0] << 8) | Query[1]));
        const auto QueryFlags = static_cast<std::uint16_t>((Query[2] << 8) | Query[3]);
        PutU16(Response, static_cast<std::uint16_t>((QueryFlags & 0x7900u) | 0x8080u));
        PutU16(Response, 1);
        PutU16(Response, 0);
        PutU16(Response, 0);
        PutU16(Response, 0);
        Response.insert(Response.end(), Query.begin() + 12,
                        Query.begin() + static_cast<std::ptrdiff_t>(Offset + 4));
        return Response;
    }

    /** @brief 累积完整 DoT 长度前缀帧，并为每帧返回拥有型 DNS NODATA 应答。 */
    struct DotDnsAnswerResponder final
    {
        std::shared_ptr<std::vector<std::uint8_t>> Pending;

        auto operator()(const std::byte *Data, const std::size_t Length)
            -> std::optional<std::vector<std::byte>>
        {
            if (Length == 0)
            {
                return std::nullopt;
            }
            const auto *Input = reinterpret_cast<const std::uint8_t *>(Data);
            Pending->insert(Pending->end(), Input, Input + Length);
            std::vector<std::byte> Output;
            std::size_t Consumed = 0;
            while (Pending->size() - Consumed >= 2)
            {
                const auto FrameBytes = static_cast<std::size_t>(
                    (static_cast<std::uint16_t>((*Pending)[Consumed]) << 8) |
                    (*Pending)[Consumed + 1]);
                if (FrameBytes < 12)
                {
                    Pending->clear();
                    return std::nullopt;
                }
                if (Pending->size() - Consumed - 2 < FrameBytes)
                {
                    break;
                }
                const auto Query = std::span<const std::uint8_t>(
                    Pending->data() + Consumed + 2, FrameBytes);
                const auto Response = BuildDnsNoDataResponse(Query);
                if (Response.empty() || Response.size() > 0xFFFFu)
                {
                    Pending->clear();
                    return std::nullopt;
                }
                Output.push_back(static_cast<std::byte>(Response.size() >> 8));
                Output.push_back(static_cast<std::byte>(Response.size() & 0xFFu));
                for (const auto Byte : Response)
                {
                    Output.push_back(static_cast<std::byte>(Byte));
                }
                Consumed += FrameBytes + 2;
            }
            if (Consumed != 0)
            {
                Pending->erase(Pending->begin(), Pending->begin() + static_cast<std::ptrdiff_t>(Consumed));
            }
            if (Output.empty())
            {
                return std::nullopt;
            }
            return Output;
        }
    };

    [[nodiscard]] auto MakeDotDnsAnswerResponder()
        -> std::function<std::optional<std::vector<std::byte>>(const std::byte *, std::size_t)>
    {
        return std::function<std::optional<std::vector<std::byte>>(const std::byte *, std::size_t)>(
            DotDnsAnswerResponder{std::make_shared<std::vector<std::uint8_t>>()});
    }

    /** @brief 复用 TLS 测试器的 HTTP 累积结果，并将查询正文转换为合法 NODATA 应答。 */
    struct DohDnsAnswerResponder final
    {
        std::function<std::optional<std::vector<std::byte>>(const std::byte *, std::size_t)> EchoResponder;
        std::string StatusLine;

        auto operator()(const std::byte *Data, const std::size_t Length)
            -> std::optional<std::vector<std::byte>>
        {
            auto EchoReply = EchoResponder(Data, Length);
            if (!EchoReply)
            {
                return std::nullopt;
            }
            const auto *ReplyText = reinterpret_cast<const char *>(EchoReply->data());
            const auto ReplyTextSize = EchoReply->size();
            const auto HeaderEnd = std::string_view(ReplyText, ReplyTextSize).find("\r\n\r\n");
            if (HeaderEnd == std::string_view::npos)
            {
                return std::vector<std::byte>{};
            }
            const auto BodyStart = HeaderEnd + 4;
            const auto BodyBytes = ReplyTextSize - BodyStart;
            const auto Query = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(EchoReply->data() + BodyStart), BodyBytes);
            const auto DnsResponse = BuildDnsNoDataResponse(Query);
            if (DnsResponse.empty())
            {
                return std::vector<std::byte>{};
            }
            auto Headers = StatusLine + "\r\nContent-Type: application/dns-message\r\nContent-Length: ";
            Headers += std::to_string(DnsResponse.size());
            Headers += "\r\n\r\n";
            std::vector<std::byte> Output;
            Output.reserve(Headers.size() + DnsResponse.size());
            for (const auto Character : Headers)
            {
                Output.push_back(static_cast<std::byte>(Character));
            }
            for (const auto Byte : DnsResponse)
            {
                Output.push_back(static_cast<std::byte>(Byte));
            }
            return Output;
        }
    };

    [[nodiscard]] auto MakeDohDnsAnswerResponder(const std::string_view StatusLine)
        -> std::function<std::optional<std::vector<std::byte>>(const std::byte *, std::size_t)>
    {
        auto EchoResponder = Prism::Testing::Tls::MakeDohResponder(StatusLine);
        return std::function<std::optional<std::vector<std::byte>>(const std::byte *, std::size_t)>(
            DohDnsAnswerResponder{std::move(EchoResponder), std::string(StatusLine)});
    }

    /**
     * @class FakeDnsServer
     * @brief 回环模拟 DNS 服务器（UDP 必备，Truncate 行为附加 TCP）。
     * @details Close 关闭监听端点与已接受连接；Drain 等待各循环协程真实退栈。
     */
    class FakeDnsServer : public std::enable_shared_from_this<FakeDnsServer>
    {
    public:
        enum class Behavior
        {
            Answer,    ///< 正常返回固定 A 记录
            EmptyAnswer, ///< 返回合法但零应答报文（模拟无记录）
            Truncate,  ///< UDP 回 TC=1，TCP 回完整应答
            Silent,    ///< 收到查询不应答（触发客户端超时）
            NxDomain,  ///< 返回 NXDOMAIN（Rcode=3，零应答）
        };

        FakeDnsServer(Net::io_context &Ioc, const Behavior BehaviorValue,
                      std::chrono::milliseconds Delay = std::chrono::milliseconds(0))
            : Ex_(Ioc.get_executor()), Tasks_(Ex_), QueryNotify_(Ex_, 1),
              Behavior_(BehaviorValue), Delay_(Delay),
              Udp_(Ioc, udp::endpoint(Net::ip::make_address("127.0.0.1"), 0))
        {
        }

        /** @brief 绑定端口并启动 UDP 循环；Truncate 行为同时启动 TCP accept 循环。 */
        auto Start() -> void
        {
            Port_ = Udp_.local_endpoint().port();
            Addr_ = Udp_.local_endpoint().address().to_string();
            auto Self = shared_from_this();
            Tasks_.Spawn(Self, Self->UdpLoop());
            if (Behavior_ == Behavior::Truncate)
            {
                Acceptor_.emplace(Ex_, tcp::endpoint(Udp_.local_endpoint().address(), Port_));
                Tasks_.Spawn(Self, Self->AcceptLoop());
            }
        }

        [[nodiscard]] auto Port() const -> std::uint16_t
        {
            return Port_;
        }

        /** @brief 返回用于断言响应来源的地址串。 */
        [[nodiscard]] auto Addr() const -> const std::string &
        {
            return Addr_;
        }

        /** @brief 构造对应的 Upstream 服务器配置。 */
        [[nodiscard]] auto MakeConfig() const -> Server
        {
            Server ServerConfig;
            ServerConfig.Address = Addr_;
            ServerConfig.Port = Port_;
            return ServerConfig;
        }

        /** @brief 等待至少一个 UDP 查询抵达，供生命周期场景释放调用方所有者。 */
        auto WaitForQuery() -> Net::awaitable<void>
        {
            (void)co_await QueryNotify_.async_receive(Net::use_awaitable);
        }

        /** @brief 关闭 UDP/TCP 监听端点及所有已接受连接，唤醒挂起的循环。 */
        auto Close() -> void
        {
            Stopped_ = true;
            boost::system::error_code ErrorCode;
            Udp_.close(ErrorCode);
            if (Acceptor_)
            {
                Acceptor_->close(ErrorCode);
            }
            for (auto &Connection : Conns_)
            {
                Connection->close(ErrorCode);
            }
        }

        /** @brief 等待 UDP、TCP accept 与已接受连接循环全部退栈。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<void>
        {
            co_await Tasks_.Drain();
        }

    private:
        /// 解析查询报文中问题段结束偏移（跳过 QNAME + QTYPE + QCLASS）
        [[nodiscard]] static auto QuestionEnd(std::span<const std::uint8_t> Query)
            -> std::size_t
        {
            std::size_t Offset = 12;
            while (Offset < Query.size() && Query[Offset] != 0)
            {
                Offset += static_cast<std::size_t>(Query[Offset]) + 1;
            }
            return Offset + 5;
        }

        /// 构造应答报文（回显问题段 + 固定 A 记录 1.2.3.4）
        [[nodiscard]] auto BuildResponse(std::span<const std::uint8_t> Query,
                                         const bool Truncate) const -> std::vector<std::uint8_t>
        {
            const auto QuestionEndOffset = QuestionEnd(Query);
            if (QuestionEndOffset > Query.size())
            {
                return {};
            }
            std::vector<std::uint8_t> Output;
            const bool Nx = Behavior_ == Behavior::NxDomain;
            const bool Full = !Truncate && Behavior_ != Behavior::EmptyAnswer && !Nx;
            PutU16(Output, static_cast<std::uint16_t>((Query[0] << 8) | Query[1]));
            // QR|RD|RA（可附加 TC 或 NXDOMAIN Rcode）。
            std::uint16_t Flags = 0x8180u;
            if (Truncate)
            {
                Flags |= 0x0200u;
            }
            if (Nx)
            {
                Flags |= 0x0003u;
            }
            PutU16(Output, Flags);
            PutU16(Output, 1); // qdcount
            std::uint16_t AnswerCount = 0;
            if (Full)
            {
                AnswerCount = 1;
            }
            PutU16(Output, AnswerCount); // ancount
            PutU16(Output, 0);
            PutU16(Output, 0);
            Output.insert(Output.end(), Query.begin() + 12,
                          Query.begin() + static_cast<std::ptrdiff_t>(QuestionEndOffset));
            if (Full)
            {
                PutU16(Output, 0xC00Cu); // 压缩指针指向问题段名字
                PutU16(Output, 1);       // type A
                PutU16(Output, 1);       // class IN
                PutU32Ttl(Output);
                PutU16(Output, 4);       // rdlength
                Output.insert(Output.end(), {1, 2, 3, 4});
            }
            return Output;
        }

        auto PutU32Ttl(std::vector<std::uint8_t> &Output) const -> void
        {
            Output.push_back(0);
            Output.push_back(0);
            Output.push_back(0);
            Output.push_back(60);
        }

        /// 延迟后发送（模拟慢上游，供 Fastest RTT 选优测试区分）
        auto MaybeDelay() -> Net::awaitable<void>
        {
            if (Delay_.count() > 0)
            {
                Net::steady_timer Timer(Ex_);
                Timer.expires_after(Delay_);
                co_await Timer.async_wait(Net::use_awaitable);
            }
        }

        auto UdpLoop() -> Net::awaitable<void>
        {
            std::vector<std::uint8_t> Buffer(4096);
            udp::endpoint Sender;
            for (;;)
            {
                boost::system::error_code ErrorCode;
                const auto ByteCount = co_await Udp_.async_receive_from(
                    Net::buffer(Buffer), Sender,
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode || Stopped_ || ByteCount < 12)
                {
                    co_return;
                }
                (void)QueryNotify_.try_send(boost::system::error_code{});
                const bool Truncate = Behavior_ == Behavior::Truncate;
                if (Behavior_ == Behavior::Silent)
                {
                    continue;
                }
                co_await MaybeDelay();
                if (Stopped_)
                {
                    co_return;
                }
                auto Response = BuildResponse({Buffer.data(), ByteCount}, Truncate);
                if (Response.empty())
                {
                    continue;
                }
                (void)co_await Udp_.async_send_to(
                    Net::buffer(Response), Sender,
                    Net::redirect_error(Net::use_awaitable, ErrorCode));
            }
        }

        auto AcceptLoop() -> Net::awaitable<void>
        {
            for (;;)
            {
                boost::system::error_code ErrorCode;
                auto Socket = std::make_shared<tcp::socket>(
                    co_await Acceptor_->async_accept(
                        Net::redirect_error(Net::use_awaitable, ErrorCode)));
                if (ErrorCode || Stopped_)
                {
                    co_return;
                }
                Conns_.push_back(Socket);
                auto Self = shared_from_this();
                Tasks_.Spawn(Self, Self->TcpConn(Socket));
            }
        }

        auto TcpConn(std::shared_ptr<tcp::socket> Socket) -> Net::awaitable<void>
        {
            for (;;)
            {
                std::array<std::uint8_t, 2> LengthBuffer{};
                boost::system::error_code ErrorCode;
                co_await Net::async_read(*Socket, Net::buffer(LengthBuffer),
                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode || Stopped_)
                {
                    co_return;
                }
                const auto Len = static_cast<std::size_t>((LengthBuffer[0] << 8) | LengthBuffer[1]);
                std::vector<std::uint8_t> Body(Len);
                co_await Net::async_read(*Socket, Net::buffer(Body),
                                         Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode || Stopped_)
                {
                    co_return;
                }
                co_await MaybeDelay();
                auto Response = BuildResponse(Body, false);
                std::vector<std::uint8_t> Frame;
                PutU16(Frame, static_cast<std::uint16_t>(Response.size()));
                Frame.insert(Frame.end(), Response.begin(), Response.end());
                (void)co_await Net::async_write(*Socket, Net::buffer(Frame),
                                                Net::redirect_error(Net::use_awaitable, ErrorCode));
            }
        }

        Net::any_io_executor Ex_;
        DnsServerTaskGroup Tasks_;
        Net::experimental::channel<void(boost::system::error_code)> QueryNotify_;
        Behavior Behavior_;
        std::chrono::milliseconds Delay_;
        udp::socket Udp_;
        std::optional<tcp::acceptor> Acceptor_; ///< 仅 Truncate 行为使用
        std::vector<std::shared_ptr<tcp::socket>> Conns_;
        std::uint16_t Port_{0};
        std::string Addr_;
        bool Stopped_{false};
    };

    struct CancellationScenario final
    {
        std::shared_ptr<Upstream> Client;
        std::shared_ptr<FakeDnsServer> First;
        std::shared_ptr<FakeDnsServer> Second;
        std::weak_ptr<Upstream> WeakOwner;
        std::exception_ptr *Failure;
        bool *OperationAborted;
        bool *OwnerExpired;
        bool *Returned;
        bool *CompletedNormally;
    };

    auto RunCancellationScenario(CancellationScenario Scenario) -> Net::awaitable<void>
    {
        try
        {
            (void)co_await Scenario.Client->Resolve("caller-cancel.example.com", QType::A);
            *Scenario.CompletedNormally = true;
        }
        catch (...)
        {
            *Scenario.Failure = std::current_exception();
            try
            {
                std::rethrow_exception(*Scenario.Failure);
            }
            catch (const boost::system::system_error &Error)
            {
                EXPECT_EQ(Error.code(), Net::experimental::error::channel_cancelled);
                *Scenario.OperationAborted = Error.code() == Net::experimental::error::channel_cancelled;
            }
            catch (const std::system_error &Error)
            {
                *Scenario.OperationAborted =
                    Error.code() == std::make_error_code(std::errc::operation_canceled);
            }
            catch (...)
            {
            }
        }
        Scenario.Client.reset();
        *Scenario.OwnerExpired = Scenario.WeakOwner.expired();
        Scenario.First->Close();
        Scenario.Second->Close();
        co_await Scenario.First->Drain();
        co_await Scenario.Second->Drain();
        *Scenario.Returned = true;
        co_return;
    }

    struct CancellationTrigger final
    {
        std::shared_ptr<FakeDnsServer> First;
        std::shared_ptr<FakeDnsServer> Second;
        std::shared_ptr<Net::cancellation_signal> Cancellation;
    };

    auto RunCancelTrigger(CancellationTrigger Trigger) -> Net::awaitable<void>
    {
        co_await Trigger.First->WaitForQuery();
        co_await Trigger.Second->WaitForQuery();
        Trigger.Cancellation->emit(Net::cancellation_type::all);
        co_return;
    }

} // namespace

















