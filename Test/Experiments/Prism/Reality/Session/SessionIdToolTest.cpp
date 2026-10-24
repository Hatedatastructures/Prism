/**
 * @file RealitySessionIdToolTest.cpp
 * @brief Reality SessionIdTool 握手契约测试
 */

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <Prism/Protocols/Reality/Detail/KeyMaterial.hpp>
#include "SessionIdTool.hpp"
#include <Prism/Transport/MemoryStream.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Reality = Prism::Reality;
    namespace SessionIdTool = Prism::Reality::Detail::Experiments;
    namespace Net = boost::asio;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::SharedTransmission;

    using ShortId = std::array<std::uint8_t, Reality::MaxShortIdLen>;

    struct HandshakeResult
    {
        Error ClientError{Error::None};
        Error ServerError{Error::None};
        ShortId ServerShortId{};
        bool ClientConnected{false};
        bool ServerConnected{false};
        bool TimedOut{false};
    };

    class HandshakeHarness
    {
    public:
        HandshakeHarness(ShortId ClientShortId, std::vector<ShortId> ServerShortIds)
            : Watchdog_(IoContext_.get_executor())
        {
            auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext_.get_executor());
            ClientEndpoint_ = std::make_shared<MemoryStream>(std::move(ClientStream));
            ServerEndpoint_ = std::make_shared<MemoryStream>(std::move(ServerStream));

            std::array<std::uint8_t, Reality::KeyLen> ServerPrivate{};
            std::array<std::uint8_t, Reality::KeyLen> ClientPrivate{};
            if (Reality::Detail::GenerateKeypair(ServerPrivate, ServerPublic_) ||
                Reality::Detail::GenerateKeypair(ClientPrivate, ClientPublic_))
            {
                throw std::runtime_error("Reality key generation failed");
            }
            ServerConfig_.private_key = ServerPrivate;
            ServerConfig_.ShortIds = std::move(ServerShortIds);
            ClientConfig_.private_key = ClientPrivate;
            ClientConfig_.ShortId = ClientShortId;

            for (std::size_t Index = 0; Index < ClientRandom_.size(); ++Index)
            {
                ClientRandom_[Index] = static_cast<std::uint8_t>(Index * 5 + 2);
            }
            for (std::size_t Index = 0; Index < Hello_.size(); ++Index)
            {
                Hello_[Index] = static_cast<std::uint8_t>(Index);
            }
        }

        auto Run() -> HandshakeResult
        {
            Watchdog_.expires_after(std::chrono::seconds(5));
            Watchdog_.async_wait([this](boost::system::error_code ErrorCode)
                                 {
                                     if (ErrorCode)
                                     {
                                         return;
                                     }
                                     Result_.TimedOut = true;
                                     CloseEndpoints();
                                 });
            Net::co_spawn(IoContext_, Handshake(), [this](std::exception_ptr ErrorValue)
                          {
                              Exception_ = ErrorValue;
                              Watchdog_.cancel();
                          });
            IoContext_.run();
            if (Exception_)
            {
                std::rethrow_exception(Exception_);
            }
            return Result_;
        }

    private:
        auto Handshake() -> Net::awaitable<void>
        {
            const SessionIdTool::HandshakeParams ClientParams{
                ClientRandom_, Hello_, ClientConfig_.ShortId};
            auto [ClientError, ClientConnection] = co_await SessionIdTool::Connect(
                {ClientEndpoint_, ClientConfig_, ServerPublic_, ClientParams});
            Result_.ClientError = ClientError;
            Result_.ClientConnected = static_cast<bool>(ClientConnection);

            const SessionIdTool::HandshakeParams ServerParams{ClientRandom_, Hello_};
            auto [ServerError, ServerShortId, ServerConnection] = co_await SessionIdTool::Accept(
                {ServerEndpoint_, ServerConfig_, ClientPublic_, ServerParams});
            Result_.ServerError = ServerError;
            Result_.ServerShortId = ServerShortId;
            Result_.ServerConnected = static_cast<bool>(ServerConnection);
            CloseEndpoints();
        }

        auto CloseEndpoints() -> void
        {
            ClientEndpoint_->Close();
            ServerEndpoint_->Close();
        }

        Net::io_context IoContext_;
        Net::steady_timer Watchdog_;
        SessionIdTool::ServerConfig ServerConfig_;
        SessionIdTool::ClientConfig ClientConfig_;
        std::array<std::uint8_t, Reality::KeyLen> ServerPublic_{};
        std::array<std::uint8_t, Reality::KeyLen> ClientPublic_{};
        std::array<std::uint8_t, 32> ClientRandom_{};
        std::array<std::uint8_t, 128> Hello_{};
        SharedTransmission ClientEndpoint_;
        SharedTransmission ServerEndpoint_;
        HandshakeResult Result_;
        std::exception_ptr Exception_;
    };

    auto RunHandshake(ShortId ClientShortId, std::vector<ShortId> ServerShortIds) -> HandshakeResult
    {
        return HandshakeHarness(ClientShortId, std::move(ServerShortIds)).Run();
    }

    class SnapshotHandshakeHarness
    {
    public:
        using ClientResultValue = std::pair<Error, SessionIdTool::SharedConn>;
        using ServerResultValue = std::tuple<Error, ShortId, SessionIdTool::SharedConn>;
        using ClientOperation = Net::awaitable<ClientResultValue>;
        using ServerOperation = Net::awaitable<ServerResultValue>;

        SnapshotHandshakeHarness() : Watchdog_(IoContext_.get_executor())
        {
            auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext_.get_executor());
            ClientEndpoint_ = std::make_shared<MemoryStream>(std::move(ClientStream));
            ServerEndpoint_ = std::make_shared<MemoryStream>(std::move(ServerStream));
            InitializeInputs();
        }

        auto Run() -> HandshakeResult
        {
            PrepareAwaitables();
            MutateInputs();
            Watchdog_.expires_after(std::chrono::seconds(5));
            Watchdog_.async_wait([this](boost::system::error_code ErrorCode)
                                 {
                                     if (ErrorCode)
                                     {
                                         return;
                                     }
                                     Result_.TimedOut = true;
                                     CloseEndpoints();
                                 });
            Net::co_spawn(IoContext_, std::move(*ClientAwaitable_),
                          [this](std::exception_ptr ErrorCode, ClientResultValue Value)
                          {
                              CompleteClient(ErrorCode, std::move(Value));
                          });
            Net::co_spawn(IoContext_, std::move(*ServerAwaitable_),
                          [this](std::exception_ptr ErrorCode, ServerResultValue Value)
                          {
                              CompleteServer(ErrorCode, std::move(Value));
                          });
            IoContext_.run();
            if (ClientException_)
            {
                std::rethrow_exception(ClientException_);
            }
            if (ServerException_)
            {
                std::rethrow_exception(ServerException_);
            }
            return Result_;
        }

    private:
        auto InitializeInputs() -> void
        {
            if (Reality::Detail::GenerateKeypair(ServerPrivate_, ServerPublic_) ||
                Reality::Detail::GenerateKeypair(ClientPrivate_, ClientPublic_) ||
                Reality::Detail::GenerateKeypair(ReplacementServerPrivate_, ReplacementServerPublic_) ||
                Reality::Detail::GenerateKeypair(ReplacementClientPrivate_, ReplacementClientPublic_))
            {
                throw std::runtime_error("Reality key generation failed");
            }

            ServerConfig_.private_key = ServerPrivate_;
            ServerConfig_.ShortIds = {ExpectedShortId_};
            ClientConfig_.private_key = ClientPrivate_;
            ClientConfig_.ShortId = ExpectedShortId_;
            for (std::size_t Index = 0; Index < ClientRandom_.size(); ++Index)
            {
                ClientRandom_[Index] = static_cast<std::uint8_t>(Index * 5 + 2);
            }
            for (std::size_t Index = 0; Index < ClientHello_.size(); ++Index)
            {
                ClientHello_[Index] = static_cast<std::uint8_t>(Index);
            }
            ServerRandom_ = ClientRandom_;
            ServerHello_ = ClientHello_;
            ClientParams_ = {ClientRandom_, ClientHello_, ExpectedShortId_};
            ServerParams_ = {ServerRandom_, ServerHello_, ExpectedShortId_};
        }

        auto PrepareAwaitables() -> void
        {
            ClientAwaitable_.emplace(SessionIdTool::Connect(
                {ClientEndpoint_, ClientConfig_, ServerPublic_, ClientParams_}));
            ServerAwaitable_.emplace(SessionIdTool::Accept(
                {ServerEndpoint_, ServerConfig_, ClientPublic_, ServerParams_}));
        }

        auto MutateInputs() -> void
        {
            ClientConfig_.private_key = ReplacementClientPrivate_;
            ClientConfig_.ShortId.fill(0x11);
            ServerConfig_.private_key = ReplacementServerPrivate_;
            ServerConfig_.ShortIds.front().fill(0x12);
            ServerPublic_ = ReplacementServerPublic_;
            ClientPublic_ = ReplacementClientPublic_;
            ClientRandom_.fill(0xA1);
            ClientHello_.fill(0xA2);
            ServerRandom_.fill(0xB1);
            ServerHello_.fill(0xB2);
            ClientParams_.ShortId.fill(0x13);
            ServerParams_.ShortId.fill(0x14);
        }

        auto CompleteClient(std::exception_ptr Exception, ClientResultValue Value) -> void
        {
            ClientException_ = Exception;
            Result_.ClientError = Value.first;
            Result_.ClientConnected = static_cast<bool>(Value.second);
            CompleteOne();
        }

        auto CompleteServer(std::exception_ptr Exception, ServerResultValue Value) -> void
        {
            ServerException_ = Exception;
            Result_.ServerError = std::get<0>(Value);
            Result_.ServerShortId = std::get<1>(Value);
            Result_.ServerConnected = static_cast<bool>(std::get<2>(Value));
            CompleteOne();
        }

        auto CompleteOne() -> void
        {
            if (--Pending_ == 0)
            {
                Watchdog_.cancel();
            }
        }

        auto CloseEndpoints() -> void
        {
            ClientEndpoint_->Close();
            ServerEndpoint_->Close();
        }

        inline static constexpr ShortId ExpectedShortId_{0x42};
        Net::io_context IoContext_;
        Net::steady_timer Watchdog_;
        SharedTransmission ClientEndpoint_;
        SharedTransmission ServerEndpoint_;
        SessionIdTool::ServerConfig ServerConfig_;
        SessionIdTool::ClientConfig ClientConfig_;
        std::array<std::uint8_t, Reality::KeyLen> ServerPrivate_{};
        std::array<std::uint8_t, Reality::KeyLen> ServerPublic_{};
        std::array<std::uint8_t, Reality::KeyLen> ClientPrivate_{};
        std::array<std::uint8_t, Reality::KeyLen> ClientPublic_{};
        std::array<std::uint8_t, Reality::KeyLen> ReplacementServerPrivate_{};
        std::array<std::uint8_t, Reality::KeyLen> ReplacementServerPublic_{};
        std::array<std::uint8_t, Reality::KeyLen> ReplacementClientPrivate_{};
        std::array<std::uint8_t, Reality::KeyLen> ReplacementClientPublic_{};
        std::array<std::uint8_t, 32> ClientRandom_{};
        std::array<std::uint8_t, 32> ServerRandom_{};
        std::array<std::uint8_t, 128> ClientHello_{};
        std::array<std::uint8_t, 128> ServerHello_{};
        SessionIdTool::HandshakeParams ClientParams_{};
        SessionIdTool::HandshakeParams ServerParams_{};
        std::optional<ClientOperation> ClientAwaitable_;
        std::optional<ServerOperation> ServerAwaitable_;
        HandshakeResult Result_;
        std::exception_ptr ClientException_;
        std::exception_ptr ServerException_;
        std::size_t Pending_{2};
    };

    TEST(RealityKeygen, AcceptsConfiguredShortId)
    {
        const ShortId ConfiguredShortId{0x42};
        const auto Result = RunHandshake(ConfiguredShortId, {ConfiguredShortId});

        ASSERT_FALSE(Result.TimedOut);
        EXPECT_EQ(Result.ClientError, Error::None);
        EXPECT_TRUE(Result.ClientConnected);
        EXPECT_EQ(Result.ServerError, Error::None);
        EXPECT_TRUE(Result.ServerConnected);
        EXPECT_EQ(Result.ServerShortId, ConfiguredShortId);
    }

    TEST(RealityKeygen, AcceptsSecondConfiguredShortId)
    {
        const ShortId FirstShortId{0x11};
        const ShortId SecondShortId{0x42};
        const auto Result = RunHandshake(SecondShortId, {FirstShortId, SecondShortId});

        ASSERT_FALSE(Result.TimedOut);
        EXPECT_EQ(Result.ClientError, Error::None);
        EXPECT_TRUE(Result.ClientConnected);
        EXPECT_EQ(Result.ServerError, Error::None);
        EXPECT_TRUE(Result.ServerConnected);
        EXPECT_EQ(Result.ServerShortId, SecondShortId);
    }

    TEST(RealityKeygen, RejectsUnconfiguredShortId)
    {
        const ShortId ConfiguredShortId{0x42};
        const ShortId ClientShortId{0x24};
        const auto Result = RunHandshake(ClientShortId, {ConfiguredShortId});

        ASSERT_FALSE(Result.TimedOut);
        EXPECT_EQ(Result.ClientError, Error::None);
        EXPECT_TRUE(Result.ClientConnected);
        EXPECT_EQ(Result.ServerError, Error::BadAuth);
        EXPECT_FALSE(Result.ServerConnected);
        EXPECT_EQ(Result.ServerShortId, ClientShortId);
    }

    TEST(RealityKeygen, RejectsEmptyShortIdAllowlist)
    {
        const ShortId ClientShortId{0x42};
        const auto Result = RunHandshake(ClientShortId, {});

        ASSERT_FALSE(Result.TimedOut);
        EXPECT_EQ(Result.ServerError, Error::BadAuth);
        EXPECT_FALSE(Result.ServerConnected);
    }

    TEST(RealityKeygen, ConnectAndAcceptSnapshotInputsAtCallTime)
    {
        const ShortId ExpectedShortId{0x42};
        const auto Result = SnapshotHandshakeHarness().Run();

        ASSERT_FALSE(Result.TimedOut);
        EXPECT_EQ(Result.ClientError, Error::None);
        EXPECT_TRUE(Result.ClientConnected);
        EXPECT_EQ(Result.ServerError, Error::None);
        EXPECT_TRUE(Result.ServerConnected);
        EXPECT_EQ(Result.ServerShortId, ExpectedShortId);
    }

} // namespace
