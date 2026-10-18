/**
 * @file VlessXudpTest.cpp
 * @brief VLESS XUDP（CommandMux）帧解析与回包封帧契约测试
 * @details 对齐 sing-vmess v0.2.5 `xudp.go` / `protocol.go` 的真实 wire：
 *          帧头 [2B Length][2B SessionId][1B Status][1B Option]，
 *          Length = 4 + [Network 1B][Port-first AddrPort][globalID?]，
 *          payload 长度在 Length 覆盖区之后独立 2 字节。
 *          地址族映射（sing-vmess AddressSerializer）：
 *          IPv4=0x01 / Fqdn=0x02 / IPv6=0x03，端口先于地址族字节。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Protocols/Vless/Xudp/Writer.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    using Prism::SharedTransmission;

    struct WriterScript final
    {
        std::vector<std::size_t> Chunks;
        std::vector<std::error_code> Errors;
        bool Block{false};
    };

    class ScriptedTransmission final : public Prism::Transmission
    {
    public:
        ScriptedTransmission(Net::any_io_executor Ex, WriterScript Script)
            : Prism::Transmission(Ex), Started_(Ex, 1), Executor_(std::move(Ex)),
              Chunks_(std::move(Script.Chunks)), Errors_(std::move(Script.Errors)),
              Block_(Script.Block), Release_(Executor_, 1)
        {
        }

        auto Executor() const -> ExecutorType override { return Executor_; }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(
                ReadInput{std::static_pointer_cast<ScriptedTransmission>(
                              Prism::Transmission::shared_from_this()),
                          Buffer},
                std::move(Handler));
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(
                WriteInput{std::static_pointer_cast<ScriptedTransmission>(
                               Prism::Transmission::shared_from_this()),
                           Buffer},
                std::move(Handler));
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transport::Detail::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{0, {}});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            Closed_ = true;
            (void)Release_.try_send(boost::system::error_code{});
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            Canceled_ = true;
            (void)Release_.try_send(boost::system::error_code{});
            return {};
        }

        [[nodiscard]] auto Closed() const noexcept -> bool { return Closed_; }
        [[nodiscard]] auto Canceled() const noexcept -> bool { return Canceled_; }
        [[nodiscard]] auto Calls() const noexcept -> std::size_t { return Calls_; }
        [[nodiscard]] auto Bytes() const noexcept -> const std::vector<std::byte> & { return Bytes_; }

        Net::experimental::channel<void(boost::system::error_code)> Started_;

    private:
        struct ReadInput final
        {
            std::shared_ptr<ScriptedTransmission> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<ScriptedTransmission> Owner;
            std::span<const std::byte> Buffer;
        };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()),
                Handler, std::move(Value));
        }
        [[nodiscard]] auto ReadPartial(std::span<std::byte>)
            -> Net::awaitable<Prism::IoResult>
        {
            co_return Prism::IoResult{
                0, Prism::Fault::FromNative(std::make_error_code(std::errc::operation_canceled))};
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
            -> Net::awaitable<Prism::IoResult>
        {
            const auto Call = Calls_++;
            (void)Started_.try_send(boost::system::error_code{});
            if (Block_ && Call == 0)
            {
                boost::system::error_code Ignored;
                co_await Release_.async_receive(Net::redirect_error(Net::use_awaitable, Ignored));
                co_return Prism::IoResult{
                    0, Prism::Fault::FromNative(std::make_error_code(std::errc::operation_canceled))};
            }
            const auto Limit = Call < Chunks_.size() ? Chunks_[Call] : Buffer.size();
            const auto Count = (std::min)(Limit, Buffer.size());
            Bytes_.insert(Bytes_.end(), Buffer.begin(),
                          Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
            const auto Error = Call < Errors_.size() ? Errors_[Call] : std::error_code{};
            co_return Prism::IoResult{Count, Prism::Fault::FromNative(Error)};
        }

        Net::any_io_executor Executor_;
        std::vector<std::size_t> Chunks_;
        std::vector<std::error_code> Errors_;
        std::vector<std::byte> Bytes_;
        Net::experimental::channel<void(boost::system::error_code)> Release_;
        std::size_t Calls_{0};
        bool Block_{false}, Closed_{false}, Canceled_{false};
    };

    struct FrameInput final
    {
        std::uint16_t SessionId{0};
        std::vector<std::uint8_t> AddressBody;
        std::vector<std::uint8_t> Payload;
        std::vector<std::uint8_t> GlobalId;
    };

    /// 组装 XUDP New 帧（首帧：network + port-first 地址 + 可选 globalID + 2B payload 长度）
    auto BuildNewFrame(FrameInput Input) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Body;
        Body.push_back(0x02U); // NetworkUDP
        Body.insert(Body.end(), Input.AddressBody.begin(), Input.AddressBody.end());
        Body.insert(Body.end(), Input.GlobalId.begin(), Input.GlobalId.end());

        std::vector<std::uint8_t> Wire;
        const auto HeaderLength = static_cast<std::uint16_t>(4U + Body.size());
        Wire.push_back(static_cast<std::uint8_t>(HeaderLength >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(HeaderLength & 0xFFU));
        Wire.push_back(static_cast<std::uint8_t>(Input.SessionId >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(Input.SessionId & 0xFFU));
        Wire.push_back(0x01U); // StatusNew
        Wire.push_back(0x01U); // OptionData
        Wire.insert(Wire.end(), Body.begin(), Body.end());
        Wire.push_back(static_cast<std::uint8_t>(Input.Payload.size() >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(Input.Payload.size() & 0xFFU));
        Wire.insert(Wire.end(), Input.Payload.begin(), Input.Payload.end());
        return Wire;
    }

    /// 组装 XUDP Keep 帧（短格式 Length=4：沿用会话目标）
    auto BuildKeepShortFrame(std::uint16_t SessionId, std::span<const std::uint8_t> Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire{0x00U, 0x04U,
                                       static_cast<std::uint8_t>(SessionId >> 8U),
                                       static_cast<std::uint8_t>(SessionId & 0xFFU),
                                       0x02U, 0x01U,
                                       static_cast<std::uint8_t>(Payload.size() >> 8U),
                                       static_cast<std::uint8_t>(Payload.size() & 0xFFU)};
        Wire.insert(Wire.end(), Payload.begin(), Payload.end());
        return Wire;
    }

    /// 组装 XUDP Keep 帧（长格式：network + port-first 地址）
    auto BuildKeepLongFrame(std::uint16_t SessionId, std::span<const std::uint8_t> AddressBody,
                            std::span<const std::uint8_t> Payload)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Body;
        Body.push_back(0x02U);
        Body.insert(Body.end(), AddressBody.begin(), AddressBody.end());

        std::vector<std::uint8_t> Wire;
        const auto HeaderLength = static_cast<std::uint16_t>(4U + Body.size());
        Wire.push_back(static_cast<std::uint8_t>(HeaderLength >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(HeaderLength & 0xFFU));
        Wire.push_back(static_cast<std::uint8_t>(SessionId >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(SessionId & 0xFFU));
        Wire.push_back(0x02U); // StatusKeep
        Wire.push_back(0x01U); // OptionData
        Wire.insert(Wire.end(), Body.begin(), Body.end());
        Wire.push_back(static_cast<std::uint8_t>(Payload.size() >> 8U));
        Wire.push_back(static_cast<std::uint8_t>(Payload.size() & 0xFFU));
        Wire.insert(Wire.end(), Payload.begin(), Payload.end());
        return Wire;
    }

    /// IPv4 port-first 地址体：[Port 2B BE][0x01][4B IPv4]
    auto Ipv4AddressBody(std::uint16_t Port, const Net::ip::address_v4 &Address)
        -> std::vector<std::uint8_t>
    {
        const auto Bytes = Address.to_bytes();
        std::vector<std::uint8_t> Body{static_cast<std::uint8_t>(Port >> 8U),
                                       static_cast<std::uint8_t>(Port & 0xFFU), 0x01U};
        Body.insert(Body.end(), Bytes.begin(), Bytes.end());
        return Body;
    }

    /// Fqdn port-first 地址体：[Port 2B BE][0x02][1B len][host]
    auto FqdnAddressBody(std::uint16_t Port, std::string_view Host)
        -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Body{static_cast<std::uint8_t>(Port >> 8U),
                                       static_cast<std::uint8_t>(Port & 0xFFU), 0x02U,
                                       static_cast<std::uint8_t>(Host.size())};
        Body.insert(Body.end(), Host.begin(), Host.end());
        return Body;
    }

    auto Ipv6AddressBody(std::uint16_t Port, const Net::ip::address_v6 &Address)
        -> std::vector<std::uint8_t>
    {
        const auto Bytes = Address.to_bytes();
        std::vector<std::uint8_t> Body{static_cast<std::uint8_t>(Port >> 8U),
                                       static_cast<std::uint8_t>(Port & 0xFFU), 0x03U};
        Body.insert(Body.end(), Bytes.begin(), Bytes.end());
        return Body;
    }

    auto WriteTestFrame(SharedTransmission ClientTransport, std::vector<std::uint8_t> Wire)
        -> Net::awaitable<void>
    {
        std::size_t Offset = 0;
        while (Offset < Wire.size())
        {
            const auto Result = co_await ClientTransport->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Wire.data() + Offset),
                    Wire.size() - Offset));
            if (Result.Failure.Failed() || Result.Bytes == 0U) co_return;
            Offset += Result.Bytes;
        }
        const auto Shutdown = co_await ClientTransport->WriteShutdown();
        if (!Shutdown) co_return;
    }

    auto MakeTransport(Net::io_context &Io, const std::vector<std::uint8_t> &Wire)
        -> std::pair<SharedTransmission, SharedTransmission>
    {
        auto [Client, Server] = Prism::MakeMemoryPair(Io.get_executor());
        auto ClientTransport = std::make_shared<Prism::MemoryStream>(std::move(Client));
        auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(Server));
        Net::co_spawn(Io, WriteTestFrame(ClientTransport, Wire), Net::detached);
        return {ClientTransport, ServerTransport};
    }

    auto CloseAndDrain(Net::io_context &Io, SharedTransmission Carrier) -> void
    {
        Io.restart();
        bool CloseAccepted = false;
        bool Drained = false;
        Prism::Testing::RunCoro(Io, [&]() -> Net::awaitable<void>
        {
            CloseAccepted = static_cast<bool>(Carrier->Close());
            const auto Result = co_await Carrier->Activity()->Drain();
            Drained = static_cast<bool>(Result);
        }());
        EXPECT_TRUE(CloseAccepted);
        EXPECT_TRUE(Drained);
    }

    auto ParseTestFrame(const std::vector<std::uint8_t> &Wire) -> bool
    {
        Net::io_context Io;
        auto [Client, Server] = MakeTransport(Io, Wire);
        std::expected<Prism::Vless::Xudp::Frame, Prism::Fault::Failure> Parsed;
        Prism::Testing::RunCoro(Io,
            [Server, &Parsed]() -> Net::awaitable<void>
            {
                Parsed = co_await Prism::Vless::Xudp::ReadFrame(Server);
            });
        (void)Client;
        return Parsed.has_value();
    }

    struct WriterScenario final
    {
        std::shared_ptr<Prism::Vless::Xudp::Writer> Owner;
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> Tasks;
        Prism::Vless::Xudp::WritePacket Packet;
        SharedTransmission Reader;
        std::size_t ReadSize{0};
        Prism::Vless::Xudp::WriteResult Result;
        std::vector<std::uint8_t> Wire;
    };

    auto RunWriterScenario(std::shared_ptr<WriterScenario> Scenario) -> Net::awaitable<void>
    {
        Scenario->Result = co_await Scenario->Owner->Send(std::move(Scenario->Packet));
        co_await Scenario->Tasks->Drain();
        if (!Scenario->Reader || Scenario->ReadSize == 0U) co_return;
        Scenario->Wire.resize(Scenario->ReadSize);
        std::size_t Done = 0;
        while (Done < Scenario->Wire.size())
        {
            const auto Result = co_await Scenario->Reader->ReadSome(
                std::span<std::byte>(reinterpret_cast<std::byte *>(Scenario->Wire.data() + Done),
                    Scenario->Wire.size() - Done));
            if (Result.Failure.Failed() || Result.Bytes == 0U) co_return;
            Done += Result.Bytes;
        }
    }

    TEST(VlessXudp, ParsesNewFrameWithPortFirstIpv4AndGlobalId)
    {
        Net::io_context Io;
        const std::array<std::uint8_t, 8> GlobalId{1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
        const std::vector<std::uint8_t> Payload{'e', 'c', 'h', 'o'};
        const auto Address = Ipv4AddressBody(443U, Net::ip::make_address_v4("127.0.0.1"));
        const auto Wire = BuildNewFrame(FrameInput{7U, Address, Payload,
            std::vector<std::uint8_t>(GlobalId.begin(), GlobalId.end())});
        auto [Client, Server] = MakeTransport(Io, Wire);

        std::expected<Prism::Vless::Xudp::Frame, Prism::Fault::Failure> Parsed;
        Prism::Testing::RunCoro(Io,
            [Server, &Parsed]() -> Net::awaitable<void>
            {
                Parsed = co_await Prism::Vless::Xudp::ReadFrame(Server);
            });

        ASSERT_TRUE(Parsed.has_value());
        EXPECT_EQ(Parsed->StatusValue, Prism::Vless::Xudp::Status::New);
        EXPECT_EQ(Parsed->SessionId, 7U);
        EXPECT_TRUE(Parsed->HasTarget);
        EXPECT_EQ(Parsed->Target.Host, *Prism::Network::ParseHost("127.0.0.1"));
        EXPECT_EQ(Parsed->Target.Port, 443U);
        EXPECT_EQ(Parsed->Payload, Payload);
        Client->CloseAndDrain(Io, Client);
    }

    TEST(VlessXudp, ParsesFqdnAddressWithPortFirst)
    {
        Net::io_context Io;
        const std::vector<std::uint8_t> Payload{'h', 'i'};
        const auto Address = FqdnAddressBody(53, "example.com");
        const auto Wire = BuildNewFrame(FrameInput{1U, Address, Payload, {}});
        auto [Client, Server] = MakeTransport(Io, Wire);

        std::expected<Prism::Vless::Xudp::Frame, Prism::Fault::Failure> Parsed;
        Prism::Testing::RunCoro(Io,
            [Server, &Parsed]() -> Net::awaitable<void>
            {
                Parsed = co_await Prism::Vless::Xudp::ReadFrame(Server);
            });

        ASSERT_TRUE(Parsed.has_value());
        EXPECT_TRUE(Parsed->HasTarget);
        EXPECT_EQ(Parsed->Target.Host, *Prism::Network::ParseHost("example.com"));
        EXPECT_EQ(Parsed->Target.Port, 53U);
        EXPECT_EQ(Parsed->Payload, Payload);
        Client->CloseAndDrain(Io, Client);
    }

    TEST(VlessXudp, ParsesKeepShortFrameReusingSessionTarget)
    {
        Net::io_context Io;
        const std::vector<std::uint8_t> Payload{'k', 'e', 'e', 'p'};
        const auto Wire = BuildKeepShortFrame(3U, Payload);
        auto [Client, Server] = MakeTransport(Io, Wire);

        std::expected<Prism::Vless::Xudp::Frame, Prism::Fault::Failure> Parsed;
        Prism::Testing::RunCoro(Io,
            [Server, &Parsed]() -> Net::awaitable<void>
            {
                Parsed = co_await Prism::Vless::Xudp::ReadFrame(Server);
            });

        ASSERT_TRUE(Parsed.has_value());
        EXPECT_EQ(Parsed->StatusValue, Prism::Vless::Xudp::Status::Keep);
        EXPECT_EQ(Parsed->SessionId, 3U);
        EXPECT_FALSE(Parsed->HasTarget);
        EXPECT_EQ(Parsed->Payload, Payload);
        Client->CloseAndDrain(Io, Client);
    }

    TEST(VlessXudp, ParsesKeepLongFrameWithPortFirstAddress)
    {
        Net::io_context Io;
        const std::vector<std::uint8_t> Payload{'l', 'o', 'n', 'g'};
        const auto Address = Ipv4AddressBody(8080U, Net::ip::make_address_v4("10.0.0.5"));
        const auto Wire = BuildKeepLongFrame(9U, Address, Payload);
        auto [Client, Server] = MakeTransport(Io, Wire);

        std::expected<Prism::Vless::Xudp::Frame, Prism::Fault::Failure> Parsed;
        Prism::Testing::RunCoro(Io,
            [Server, &Parsed]() -> Net::awaitable<void>
            {
                Parsed = co_await Prism::Vless::Xudp::ReadFrame(Server);
            });

        ASSERT_TRUE(Parsed.has_value());
        EXPECT_EQ(Parsed->StatusValue, Prism::Vless::Xudp::Status::Keep);
        EXPECT_EQ(Parsed->SessionId, 9U);
        EXPECT_TRUE(Parsed->HasTarget);
        EXPECT_EQ(Parsed->Target.Host, *Prism::Network::ParseHost("10.0.0.5"));
        EXPECT_EQ(Parsed->Target.Port, 8080U);
        EXPECT_EQ(Parsed->Payload, Payload);
        Client->CloseAndDrain(Io, Client);
    }

    TEST(VlessXudp, WritesKeepFrameWithSessionIdAndPortFirstSourceAddress)
    {
        Net::io_context Io;
        auto [Client, Server] = Prism::MakeMemoryPair(Io.get_executor());
        auto ServerTransport = std::make_shared<Prism::MemoryStream>(std::move(Server));
        auto ClientTransport = std::make_shared<Prism::MemoryStream>(std::move(Client));
        const std::vector<std::uint8_t> Payload{'p', 'o', 'n', 'g'};
        const auto Source = Net::ip::udp::endpoint(Net::ip::make_address_v4("127.0.0.1"), 41000);

        constexpr std::size_t ExpectedSize = 2U + 2U + 1U + 1U + 1U + 7U + 2U + 4U;
        auto Tasks = std::make_shared<Prism::Lifecycle::TaskRegistry>(ServerTransport->Executor());
        auto Writer = std::make_shared<Prism::Vless::Xudp::Writer>(ServerTransport, Tasks);
        auto Scenario = std::make_shared<WriterScenario>();
        Scenario->Owner = std::move(Writer);
        Scenario->Tasks = std::move(Tasks);
        Scenario->Packet = {Prism::Vless::Xudp::EncodeReply({5U, Source, Payload}), Payload.size()};
        Scenario->Reader = std::move(ClientTransport);
        Scenario->ReadSize = ExpectedSize;
        Prism::Testing::RunCoro(Io, RunWriterScenario(Scenario));
        EXPECT_TRUE(Scenario->Result.Written);
        auto Wire = std::move(Scenario->Wire);

        ASSERT_EQ(Wire.size(), 20U);
        EXPECT_EQ(Wire[0], 0x00U);
        EXPECT_EQ(Wire[1], 0x0CU);
        EXPECT_EQ(Wire[2], 0x00U);
        EXPECT_EQ(Wire[3], 0x05U);
        EXPECT_EQ(Wire[4], 0x02U);
        EXPECT_EQ(Wire[5], 0x01U);
        EXPECT_EQ(Wire[6], 0x02U);
        EXPECT_EQ(Wire[7], 0xA0U);
        EXPECT_EQ(Wire[8], 0x28U);
        EXPECT_EQ(Wire[9], 0x01U);
        EXPECT_EQ(Wire[10], 127U);
        EXPECT_EQ(Wire[11], 0U);
        EXPECT_EQ(Wire[12], 0U);
        EXPECT_EQ(Wire[13], 1U);
        EXPECT_EQ(Wire[14], 0x00U);
        EXPECT_EQ(Wire[15], 0x04U);
        EXPECT_EQ(std::vector<std::uint8_t>(Wire.begin() + 16, Wire.end()), Payload);
        ServerTransport->CloseAndDrain(Io, ServerTransport);
    }

    TEST(VlessXudp, ParsesIpv6AndWritesIpv6SourceAddress)
    {
        Net::io_context Io;
        const auto AddressValue = Net::ip::make_address_v6("2001:db8::7");
        const std::vector<std::uint8_t> Payload{'v', '6'};
        const auto Wire = BuildNewFrame(
            FrameInput{12U, Ipv6AddressBody(5353U, AddressValue), Payload, {}});
        auto [Client, Server] = MakeTransport(Io, Wire);

        std::expected<Prism::Vless::Xudp::Frame, Prism::Fault::Failure> Parsed;
        Prism::Testing::RunCoro(Io,
            [Server, &Parsed]() -> Net::awaitable<void>
            {
                Parsed = co_await Prism::Vless::Xudp::ReadFrame(Server);
            });

        ASSERT_TRUE(Parsed.has_value());
        EXPECT_TRUE(Parsed->HasTarget);
        EXPECT_EQ(Parsed->Target.Host, *Prism::Network::ParseHost("2001:db8::7"));
        EXPECT_EQ(Parsed->Target.Port, 5353U);
        EXPECT_EQ(Parsed->Payload, Payload);

        const auto Reply = Prism::Vless::Xudp::EncodeReply({12U,
            Net::ip::udp::endpoint(AddressValue, 5353U), Payload});
        ASSERT_EQ(Reply.size(), 30U);
        EXPECT_EQ(Reply[0], std::byte{0});
        EXPECT_EQ(Reply[1], std::byte{24});
        EXPECT_EQ(Reply[4], std::byte{2});
        EXPECT_EQ(Reply[6], std::byte{2});
        EXPECT_EQ(Reply[9], std::byte{3});
        for (std::size_t Index = 0; Index < 16U; ++Index)
        {
            EXPECT_EQ(Reply[10U + Index], std::byte{AddressValue.to_bytes()[Index]});
        }
        Client->CloseAndDrain(Io, Client);
    }

    TEST(VlessXudp, RejectsTruncatedAndErrorOptionFrames)
    {
        const auto Address = Ipv4AddressBody(53U, Net::ip::make_address_v4("127.0.0.1"));
        const std::vector<std::uint8_t> ShortPayload{1U, 2U, 3U};
        const std::vector<std::uint8_t> EmptyPayload;
        auto Truncated = BuildNewFrame(FrameInput{4U, Address, ShortPayload, {}});
        Truncated.pop_back();
        EXPECT_FALSE(ParseTestFrame(Truncated));

        auto ErrorFrame = BuildKeepShortFrame(4U, EmptyPayload);
        ErrorFrame[5] = Prism::Vless::Xudp::OptionError;
        EXPECT_FALSE(ParseTestFrame(ErrorFrame));

        auto UnknownStatus = BuildKeepShortFrame(4U, EmptyPayload);
        UnknownStatus[4] = 0x7FU;
        EXPECT_FALSE(ParseTestFrame(UnknownStatus));
    }

    TEST(VlessXudp, WriterCompletesAcrossPartialWrites)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransmission>(Io.get_executor(),
            WriterScript{{3U, 2U, 100U}, {}, false});
        auto Tasks = std::make_shared<Prism::Lifecycle::TaskRegistry>(Io.get_executor());
        auto Writer = std::make_shared<Prism::Vless::Xudp::Writer>(Transport, Tasks);
        auto Scenario = std::make_shared<WriterScenario>();
        Scenario->Owner = std::move(Writer);
        Scenario->Tasks = std::move(Tasks);
        Scenario->Packet = {{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}, std::byte{5}}, 2U};
        std::exception_ptr Failure;
        Net::co_spawn(Io, RunWriterScenario(Scenario),
            [&Failure](std::exception_ptr Error) { Failure = Error; });
        Io.run();

        EXPECT_FALSE(Failure);
        EXPECT_TRUE(Scenario->Result.Written);
        EXPECT_EQ(Scenario->Result.Bytes, 2U);
        ASSERT_EQ(Transport->Bytes().size(), 5U);
        EXPECT_EQ(Transport->Calls(), 2U);
        EXPECT_FALSE(Transport->Closed());
    }

    TEST(VlessXudp, WriterPropagatesWriteErrorAndClosesTransport)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransmission>(Io.get_executor(),
            WriterScript{{3U, 0U}, {std::error_code{}, std::make_error_code(std::errc::io_error)}, false});
        auto Tasks = std::make_shared<Prism::Lifecycle::TaskRegistry>(Io.get_executor());
        auto Writer = std::make_shared<Prism::Vless::Xudp::Writer>(Transport, Tasks);
        auto Scenario = std::make_shared<WriterScenario>();
        Scenario->Owner = std::move(Writer);
        Scenario->Tasks = std::move(Tasks);
        Scenario->Packet = {{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}, std::byte{5}}, 2U};
        std::exception_ptr Failure;
        Net::co_spawn(Io, RunWriterScenario(Scenario),
            [&Failure](std::exception_ptr Error) { Failure = Error; });
        Io.run();

        EXPECT_FALSE(Failure);
        EXPECT_FALSE(Scenario->Result.Written);
        EXPECT_TRUE(Transport->Closed());
        EXPECT_TRUE(Transport->Canceled());
        EXPECT_EQ(Transport->Calls(), 2U);
    }

    TEST(VlessXudp, WriterCancelCompletesPendingProducer)
    {
        Net::io_context Io;
        auto Transport = std::make_shared<ScriptedTransmission>(Io.get_executor(),
            WriterScript{{}, {}, true});
        auto Tasks = std::make_shared<Prism::Lifecycle::TaskRegistry>(Io.get_executor());
        auto Writer = std::make_shared<Prism::Vless::Xudp::Writer>(Transport, Tasks);
        auto Scenario = std::make_shared<WriterScenario>();
        Scenario->Owner = std::move(Writer);
        Scenario->Tasks = std::move(Tasks);
        Scenario->Packet = {{std::byte{1}, std::byte{2}, std::byte{3}}, 1U};
        std::exception_ptr Failure;
        Net::co_spawn(Io, RunWriterScenario(Scenario),
            [&Failure](std::exception_ptr Error) { Failure = Error; });
        Net::co_spawn(Io,
            [Owner = Scenario->Owner, Transport]() -> Net::awaitable<void>
            {
                co_await Transport->Started_.async_receive(Net::use_awaitable);
                Owner->Close();
            },
            [&Failure](std::exception_ptr Error) { Failure = Error; });
        Io.run();

        EXPECT_FALSE(Failure);
        EXPECT_FALSE(Scenario->Result.Written);
        EXPECT_TRUE(Transport->Closed());
        EXPECT_TRUE(Transport->Canceled());
    }

} // namespace
