#pragma once

/**
 * @file VmessConnSessionSupport.hpp
 * @brief VMess Conn 与数据报测试共享的有主传输和任务辅助。
 * @details 原始线协议辅助只借用 shared owner；测试任务保存完成状态，确保
 *          io_context 退出前所有自启协程都已结束。
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <expected>
#include <exception>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <Prism/Account/Account.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include "../../../Transport/Core/TransportResources.hpp"

namespace
{
    namespace Net = boost::asio;
    namespace Vmess = Prism::Vmess;
    using Prism::AsBytes;
    using Prism::AsU8;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::MemoryStream;
    using VmessTransportPair = Prism::Testing::OwnedTransportPair;
    using VmessCloseReceipt = Prism::Testing::FixtureCloseReceipt;
    using DatagramRunResult = Prism::Contract::Io::PacketTransferResult;

    /** @brief 统一把 VMess packet result 映射为测试使用的稳定 Fault 分类。 */
    auto DatagramStatus(const DatagramRunResult& Result) -> Prism::Fault::Code
    {
        return Result.Failure.Code;
    }

    auto FaultStatus(Error Value) -> Prism::Fault::Code
    {
        return Prism::Fault::ToCode(Prism::make_error_code(Value));
    }

    /** @brief 运行顶层测试协程直至完成，并重抛其异常。 */
    template <typename Awaitable>
    auto RunCoroutine(Net::io_context& Context, Awaitable Coroutine) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(
            Context, std::move(Coroutine),
            [&Failure](std::exception_ptr ErrorValue)
            {
                Failure = std::move(ErrorValue);
            });
        Context.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /**
     * @brief 启动并等待一个带结果的 VMess 测试协程。
     * @tparam Result 子任务返回的测试结果类型。
     * @details 完成回调在等待方仍存活时写入结果，再通知通道；异常由 Wait 重抛。
     */
    template <typename Result>
    class VmessTestTask final
    {
    public:
        explicit VmessTestTask(Net::any_io_executor Executor)
            : Executor_(std::move(Executor)), Completed_(Executor_, 1)
        {
        }

        /** @brief 在固定 executor 上启动子任务。 */
        auto Start(Net::awaitable<Result> Coroutine) -> void
        {
            Net::co_spawn(
                Executor_, std::move(Coroutine),
                [this](std::exception_ptr Failure, Result Value)
                {
                    Failure_ = std::move(Failure);
                    if (!Failure_)
                    {
                        Result_.emplace(std::move(Value));
                    }
                    (void)Completed_.try_send(boost::system::error_code{});
                });
        }

        /** @brief 等待任务终止并取回唯一结果。 */
        [[nodiscard]] auto Wait() -> Net::awaitable<Result>
        {
            co_await Completed_.async_receive(Net::use_awaitable);
            if (Failure_)
            {
                std::rethrow_exception(Failure_);
            }
            if (!Result_)
            {
                throw std::logic_error("VMess test task completed without a result");
            }
            co_return std::move(*Result_);
        }

    private:
        Net::any_io_executor Executor_;
        Net::experimental::channel<void(boost::system::error_code)> Completed_;
        std::exception_ptr Failure_;
        std::optional<Result> Result_;
    };

    /** @brief 用真实测试 io_context executor 创建双端 shared MemoryStream。 */
    [[nodiscard]] auto MakeVmessTransportPair(Net::io_context& Context) -> VmessTransportPair
    {
        return Prism::Testing::MakeOwnedTransportPair(Context.get_executor());
    }

    /** @brief 在共享端点 owner 上分别执行最终关闭和活动 Drain。 */
    struct VmessEndpointCloseReceipts final
    {
        VmessCloseReceipt First;
        VmessCloseReceipt Second;
    };

    [[nodiscard]] auto CloseVmessEndpoints(VmessTransportPair Pair)
        -> Net::awaitable<VmessEndpointCloseReceipts>
    {
        const auto First = co_await Prism::Testing::CloseFixture(Pair.FirstOwner);
        const auto Second = co_await Prism::Testing::CloseFixture(Pair.SecondOwner);
        co_return VmessEndpointCloseReceipts{First, Second};
    }

    /** @brief 分别关闭 VMess 数据报包装层与其 Conn owner，并等待两层 Drain。 */
    struct VmessDatagramCloseReceipts final
    {
        VmessCloseReceipt Datagram;
        VmessCloseReceipt Connection;
    };

    [[nodiscard]] auto CloseVmessDatagram(Vmess::SharedDgram Datagram)
        -> Net::awaitable<VmessDatagramCloseReceipts>
    {
        const auto Connection = Datagram->Stream();
        const auto DatagramReceipt = co_await Prism::Testing::CloseFixture(Datagram);
        const auto ConnectionReceipt = co_await Prism::Testing::CloseFixture(Connection);
        co_return VmessDatagramCloseReceipts{DatagramReceipt, ConnectionReceipt};
    }

    using VmessStreamAcceptResult =
        std::expected<Vmess::AcceptedConnection, Prism::Fault::Failure>;
    using VmessDatagramAcceptResult =
        std::expected<Vmess::AcceptedDatagram, Prism::Fault::Failure>;

    /** @brief 驱动唯一服务端入口并要求原输入得到 stream command。 */
    [[nodiscard]] auto AcceptVmessStream(
        Prism::SharedTransmission Upstream, Vmess::ServerConfig Config)
        -> Net::awaitable<VmessStreamAcceptResult>
    {
        auto Result = co_await Vmess::AcceptSession(std::move(Upstream), Config);
        if (!Result) co_return std::unexpected(Result.error());
        if (auto* Stream = std::get_if<Vmess::AcceptedConnection>(&*Result))
            co_return std::move(*Stream);
        auto Datagram = std::move(std::get<Vmess::AcceptedDatagram>(*Result).Connection);
        const auto Receipts = co_await CloseVmessDatagram(std::move(Datagram));
        Prism::Testing::ExpectFixtureCloseReceipt(Receipts.Datagram);
        Prism::Testing::ExpectFixtureCloseReceipt(Receipts.Connection);
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
    }

    /** @brief 驱动唯一服务端入口并要求原输入得到 UDP command。 */
    [[nodiscard]] auto AcceptVmessDatagram(
        Prism::SharedTransmission Upstream, Vmess::ServerConfig Config)
        -> Net::awaitable<VmessDatagramAcceptResult>
    {
        auto Result = co_await Vmess::AcceptSession(std::move(Upstream), Config);
        if (!Result) co_return std::unexpected(Result.error());
        if (auto* Datagram = std::get_if<Vmess::AcceptedDatagram>(&*Result))
            co_return std::move(*Datagram);
        auto Connection = std::move(
            std::get<Vmess::AcceptedConnection>(*Result).Connection);
        const auto Receipt = co_await Prism::Testing::CloseFixture(Connection);
        Prism::Testing::ExpectFixtureCloseReceipt(Receipt);
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
    }

    /** @brief 测试 UUID，使用可识别的递增字节。 */
    [[nodiscard]] auto TestUuid() -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Uuid{};
        for (std::size_t Index = 0; Index < Uuid.size(); ++Index)
        {
            Uuid[Index] = static_cast<std::uint8_t>(0x20 + Index);
        }
        return Uuid;
    }

    /** @brief 将 UUID 转成账户目录使用的字节视图。 */
    [[nodiscard]] auto CredentialUuid(const std::array<std::uint8_t, 16>& Uuid)
        -> std::array<std::byte, 16>
    {
        std::array<std::byte, 16> Result{};
        for (std::size_t Index = 0; Index < Result.size(); ++Index)
        {
            Result[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        return Result;
    }

    /** @brief 构造 VMess 目标地址。 */
    [[nodiscard]] auto MakeAddress(Vmess::AddressType Type, std::string Host, std::uint16_t Port)
        -> Vmess::Address
    {
        Vmess::Address Address{};
        Address.Type = Type;
        Address.Host = std::move(Host);
        Address.Port = Port;
        return Address;
    }

    /** @brief 精确读取指定字节数；短读、EOF 和传输错误返回 true。 */
    [[nodiscard]] auto RecvExact(
        const std::shared_ptr<MemoryStream>& Stream,
        std::span<std::uint8_t> Destination) -> Net::awaitable<bool>
    {
        std::size_t Done = 0;
        while (Done < Destination.size())
        {
            const auto Read = co_await Stream->ReadSome(AsBytes(Destination.subspan(Done)));
            if (Read.Failure.Failed() || Read.Bytes == 0)
            {
                co_return true;
            }
            Done += Read.Bytes;
        }
        co_return false;
    }

    /** @brief 原始客户端握手所需的随机密钥、nonce、版本和 wire 数据。 */
    struct RawClientHandshake final
    {
        std::array<std::uint8_t, 16> Iv{};
        std::array<std::uint8_t, 16> Key{};
        std::uint8_t Version{};
        std::uint8_t Option{};
        std::vector<std::uint8_t> Wire;
    };

    /** @brief 构造 AEAD 认证头，保持原始客户端的随机输入方式。 */
    [[nodiscard]] auto MakeRawClientHandshake(
        const std::array<std::uint8_t, 16>& Uuid) -> RawClientHandshake
    {
        std::random_device Random;
        RawClientHandshake Handshake;
        for (auto& Byte : Handshake.Iv)
        {
            Byte = static_cast<std::uint8_t>(Random() & 0xFF);
        }
        for (auto& Byte : Handshake.Key)
        {
            Byte = static_cast<std::uint8_t>(Random() & 0xFF);
        }
        Handshake.Version = static_cast<std::uint8_t>(Random() & 0xFF);
        const auto Padding = static_cast<std::uint8_t>(Random() % 16);
        std::array<std::uint8_t, 4> RandomBytes{};
        for (auto& Byte : RandomBytes)
        {
            Byte = static_cast<std::uint8_t>(Random() & 0xFF);
        }
        Handshake.Option = static_cast<std::uint8_t>(Vmess::Option::ChunkStream) |
                           static_cast<std::uint8_t>(Vmess::Option::ChunkMasking);

        Vmess::RequestHeader Header;
        Header.Version = Vmess::ProtocolVersion;
        Header.Cmd = static_cast<std::uint8_t>(Vmess::Command::Tcp);
        Header.opt = Handshake.Option;
        Header.sec = Vmess::Security::Aes128Gcm;
        Header.Target = MakeAddress(Vmess::AddressType::Domain, "example.com", 443);
        const auto Plain = Vmess::BuildRequestHeader(
            Header, Vmess::RequestMeta{Handshake.Iv, Handshake.Key, Handshake.Version, Padding});
        const auto CommandKey = Vmess::CmdKeyFromUuid(Uuid);
        const auto TimeSeconds = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        Handshake.Wire = Vmess::SealAuthHeader(
            CommandKey, Vmess::AuthHeaderInput{Plain, TimeSeconds, RandomBytes});
        return Handshake;
    }

    /** @brief 发送认证头并验证服务端响应长度块和响应头。 */
    [[nodiscard]] auto CompleteRawClientHandshake(
        const std::shared_ptr<MemoryStream>& Stream,
        const RawClientHandshake& Handshake) -> Net::awaitable<bool>
    {
        const auto HeaderWrite = co_await Stream->WriteSome(AsBytes(
            std::span<const std::uint8_t>(Handshake.Wire)));
        if (HeaderWrite.Failure.Failed())
        {
            co_return false;
        }

        std::array<std::uint8_t, 18> LengthEncrypted{};
        if (co_await RecvExact(Stream, LengthEncrypted))
        {
            co_return false;
        }
        const auto ResponseBodyKey = Vmess::detail::Sha256(Handshake.Key);
        const auto ResponseBodyIv = Vmess::detail::Sha256(Handshake.Iv);
        std::array<std::uint8_t, 16> ResponseKey16{};
        std::memcpy(ResponseKey16.data(), ResponseBodyKey.data(), ResponseKey16.size());
        std::array<std::uint8_t, 16> ResponseIv16{};
        std::memcpy(ResponseIv16.data(), ResponseBodyIv.data(), ResponseIv16.size());
        const auto ResponseLengthKey = Vmess::Kdf(ResponseKey16, Vmess::KdfRespLenKey);
        const auto ResponseLengthIv = Vmess::Kdf(ResponseIv16, Vmess::KdfRespLenIv);
        std::array<std::uint8_t, 16> LengthKey{};
        std::memcpy(LengthKey.data(), ResponseLengthKey.data(), LengthKey.size());
        std::array<std::uint8_t, 12> LengthIv{};
        std::memcpy(LengthIv.data(), ResponseLengthIv.data(), LengthIv.size());
        const auto LengthPlain = Vmess::detail::AesGcmOpen(
            Vmess::detail::OpenInput{LengthKey, LengthIv, LengthEncrypted, {}});
        if (LengthPlain.size() != 2)
        {
            co_return false;
        }

        const auto ResponseLength = (static_cast<std::size_t>(LengthPlain[0]) << 8) |
                                    static_cast<std::size_t>(LengthPlain[1]);
        std::vector<std::uint8_t> ResponseEncrypted(ResponseLength + 16);
        if (co_await RecvExact(Stream, ResponseEncrypted))
        {
            co_return false;
        }
        const auto ResponseKey = Vmess::Kdf(ResponseKey16, Vmess::KdfRespKey);
        const auto ResponseIv = Vmess::Kdf(ResponseIv16, Vmess::KdfRespIv);
        std::array<std::uint8_t, 16> Key{};
        std::memcpy(Key.data(), ResponseKey.data(), Key.size());
        std::array<std::uint8_t, 12> Iv{};
        std::memcpy(Iv.data(), ResponseIv.data(), Iv.size());
        Vmess::ResponseHeader Header;
        const auto ErrorValue = Vmess::OpenResponseHeader(
            Key, Vmess::RespHeaderParseInput{Iv, ResponseEncrypted}, Header);
        co_return ErrorValue == Error::None && Header.Version == Handshake.Version;
    }

    /** @brief 在握手成功后发送一个数据块和结束块。 */
    [[nodiscard]] auto SendRawClientChunks(
        const std::shared_ptr<MemoryStream>& Stream,
        const RawClientHandshake& Handshake,
        const std::string& Payload) -> Net::awaitable<bool>
    {
        Vmess::ChunkEncryptor Encryptor(
            std::span<const std::uint8_t, 16>(Handshake.Key),
            std::span<const std::uint8_t, 16>(Handshake.Iv), Handshake.Option);
        std::vector<std::uint8_t> Chunk(Payload.size() + Vmess::ChunkEncryptor::Overhead);
        const auto EncryptedSize = Encryptor.Seal(
            std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(Payload.data()), Payload.size()),
            Chunk);
        const auto ChunkWrite = co_await Stream->WriteSome(AsBytes(
            std::span<const std::uint8_t>(Chunk).first(EncryptedSize)));
        if (ChunkWrite.Failure.Failed())
        {
            co_return false;
        }
        std::array<std::uint8_t, 34> EndBlock{};
        const auto EndSize = Encryptor.Finish(EndBlock);
        const auto EndWrite = co_await Stream->WriteSome(AsBytes(
            std::span<const std::uint8_t>(EndBlock).first(EndSize)));
        co_return !EndWrite.Failure.Failed();
    }

    /** @brief 原始客户端执行认证头、响应校验、数据块和结束块。 */
    [[nodiscard]] auto RunRawClient(
        const std::shared_ptr<MemoryStream>& Stream,
        const std::array<std::uint8_t, 16>& Uuid,
        const std::string& Payload) -> Net::awaitable<bool>
    {
        const auto Handshake = MakeRawClientHandshake(Uuid);
        if (!(co_await CompleteRawClientHandshake(Stream, Handshake)))
        {
            co_return false;
        }
        co_return co_await SendRawClientChunks(Stream, Handshake, Payload);
    }
} // namespace
