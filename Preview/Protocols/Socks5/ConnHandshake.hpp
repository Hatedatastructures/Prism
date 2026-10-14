/**
 * @file ConnHandshake.hpp
 * @brief SOCKS5 握手、请求和响应状态机 owner
 * @details 拥有客户端 BND、服务端解析请求、握手完成状态和复用的发送
 *          缓冲；底层字节读写由 ConnTransport 提供，RFC1929 认证由
 *          ConnAuth 提供。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Common/Address.hpp>
#include <Preview/Protocols/Common/ExactIo.hpp>
#include <Preview/Protocols/Socks5/BeastCodec.hpp>
#include <Preview/Protocols/Socks5/ConnAuth.hpp>
#include <Preview/Protocols/Socks5/ConnTransport.hpp>
#include <Preview/Protocols/Socks5/Types.hpp>

namespace Preview::Socks5
{

    /**
     * @class ConnHandshake
     * @brief SOCKS5 客户端/服务端握手状态 owner
     * @tparam Memory 会话内存策略
     */
    template <Preview::Memory::Restrict Memory>
    class ConnHandshake final
    {
    public:
        explicit ConnHandshake(Memory &MemoryValue)
            : TxWire_(MemoryValue.Arena())
        {
        }

        [[nodiscard]] auto IsHandshaken() const noexcept -> bool
        {
            return Handshaken_;
        }

        [[nodiscard]] auto Parsed() const -> const Request &
        {
            return Req_;
        }

        [[nodiscard]] auto BindEndpoint() const -> const Address &
        {
            return Bind_;
        }

        /// 客户端握手输入；传输和认证 owner 借用至 coroutine 完成，其余值由 frame 持有。
        struct WriteHandshakeRequest final
        {
            ConnTransport<Memory> &Transport;
            ConnAuth<Memory> &Auth;
            Request Target;
            ClientConfig Config;
        };

        /**
         * @brief 客户端握手：Greeting、方法选择、认证、请求和响应
         * @param Input 传输/认证借用与按值拥有的请求配置
         * @return 错误码
         */
        [[nodiscard]] auto WriteHandshake(WriteHandshakeRequest Input)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            Greeting GreetingValue;
            GreetingValue.Ver = Version;
            GreetingValue.Methods = Input.Config.EnableAuth
                                        ? std::vector<std::uint8_t>{
                                              static_cast<std::uint8_t>(AuthMethod::UserPass)}
                                        : std::vector<std::uint8_t>{
                                              static_cast<std::uint8_t>(AuthMethod::NoAuth)};
            BuildGreeting(GreetingValue, TxWire_);
            if (TxWire_.empty())
            {
                co_return std::unexpected(ProtocolFailure(Error::BadLength));
            }
            auto Written = co_await Input.Transport.SendBytes(TxWire_);
            if (Written.Failure.Failed())
            {
                co_return std::unexpected(Written.Failure);
            }

            std::array<std::uint8_t, 2> Selection{};
            auto Read = co_await Input.Transport.ReadExact(std::span<std::uint8_t>(Selection));
            if (Read.Failure.Failed())
            {
                co_return std::unexpected(Read.Failure);
            }
            if (Read.Bytes != Selection.size())
                co_return std::unexpected(ProtocolFailure(Error::BadMessage));
            if (Selection[0] != Version)
            {
                co_return std::unexpected(ProtocolFailure(Error::BadMagic));
            }
            const auto ExpectedMethod = Input.Config.EnableAuth
                                            ? static_cast<std::uint8_t>(AuthMethod::UserPass)
                                            : static_cast<std::uint8_t>(AuthMethod::NoAuth);
            if (Selection[1] != ExpectedMethod)
            {
                co_return std::unexpected(ProtocolFailure(Error::Unsupported));
            }

            if (Selection[1] == static_cast<std::uint8_t>(AuthMethod::UserPass))
            {
                BuildUserpass(Input.Config.Username, Input.Config.Password, TxWire_);
                if (TxWire_.empty())
                {
                    co_return std::unexpected(ProtocolFailure(Error::BadLength));
                }
                Written = co_await Input.Transport.SendBytes(TxWire_);
                if (Written.Failure.Failed())
                {
                    co_return std::unexpected(Written.Failure);
                }
                std::array<std::uint8_t, 2> Response{};
                Read = co_await Input.Transport.ReadExact(std::span<std::uint8_t>(Response));
                if (Read.Failure.Failed())
                {
                    co_return std::unexpected(Read.Failure);
                }
                if (Read.Bytes != Response.size())
                    co_return std::unexpected(ProtocolFailure(Error::BadMessage));
                if (Response[0] != 0x01 || Response[1] != 0x00)
                {
                    co_return std::unexpected(ProtocolFailure(Error::BadAuth));
                }
            }

            BuildRequest(Input.Target, TxWire_);
            if (TxWire_.empty())
            {
                co_return std::unexpected(ProtocolFailure(Error::BadAddress));
            }
            Written = co_await Input.Transport.SendBytes(TxWire_);
            if (Written.Failure.Failed())
            {
                co_return std::unexpected(Written.Failure);
            }

            const auto ReplyValue = co_await ReadReply(Input.Transport);
            if (!ReplyValue)
            {
                co_return std::unexpected(ReplyValue.error());
            }
            if (ReplyValue->Code != ReplyCode::Success)
            {
                co_return std::unexpected(FailureFromReplyCode(ReplyValue->Code));
            }
            Bind_ = ReplyValue->Bind;
            Handshaken_ = true;
            (void)Input.Auth;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        /**
         * @brief 服务端握手：方法协商、RFC1929、请求解析和响应
         * @param Transport 底层传输 owner
         * @param Auth 认证租约 owner
         * @param Config 服务端命令和认证配置
         * @return 错误码与解析请求
         */
        [[nodiscard]] auto ReadHandshake(
            ConnTransport<Memory> &Transport,
            ConnAuth<Memory> &Auth,
            const ServerConfig &Config)
            -> Net::awaitable<std::expected<Request, Preview::Fault::Failure>>
        {
            auto GreetingMessage = co_await ReadMessage(Transport, Message::Kind::Greeting);
            if (!GreetingMessage) co_return std::unexpected(GreetingMessage.error());

            const auto SelectedMethod = Config.EnableAuth
                                            ? static_cast<std::uint8_t>(AuthMethod::UserPass)
                                            : static_cast<std::uint8_t>(AuthMethod::NoAuth);
            const auto &Methods = GreetingMessage->Methods;
            const bool Acceptable = std::find(Methods.begin(), Methods.end(), SelectedMethod) !=
                                    Methods.end();
            if (!Acceptable)
            {
                const auto ReplyError = co_await SendMethodReply(
                    Transport, static_cast<std::uint8_t>(AuthMethod::NoAcceptable));
                if (!ReplyError)
                {
                    co_return std::unexpected(ReplyFailureValue(ReplyError.error()));
                }
                co_return std::unexpected(ProtocolFailure(Error::Unsupported));
            }

            const auto MethodReply = co_await SendMethodReply(Transport, SelectedMethod);
            if (!MethodReply)
            {
                co_return std::unexpected(ReplyFailureValue(MethodReply.error()));
            }
            if (SelectedMethod == static_cast<std::uint8_t>(AuthMethod::UserPass))
            {
                const auto Authentication = co_await Auth.UserpassAuth(
                    Transport, Config.Authenticator);
                if (!Authentication)
                {
                    co_return std::unexpected(Authentication.error());
                }
            }

            auto RequestMessage = co_await ReadMessage(Transport, Message::Kind::Request);
            if (!RequestMessage)
            {
                (void)co_await SendReply(Transport, ReplyCode::GeneralFailure);
                co_return std::unexpected(RequestMessage.error());
            }
            Request RequestValue;
            RequestValue.Cmd = RequestMessage->Cmd;
            RequestValue.Target = RequestMessage->AddressValue;
            if (RequestValue.Cmd == Command::Connect && !Config.EnableTcp)
            {
                (void)co_await SendReply(Transport, ReplyCode::CommandNotSupported);
                co_return std::unexpected(ProtocolFailure(Error::Unsupported));
            }
            if (RequestValue.Cmd == Command::UdpAssociate && !Config.EnableUdp)
            {
                (void)co_await SendReply(Transport, ReplyCode::CommandNotSupported);
                co_return std::unexpected(ProtocolFailure(Error::Unsupported));
            }
            if (!Config.DeferConnectReply)
            {
                const auto ReplyError = co_await SendReply(Transport, ReplyCode::Success);
                if (!ReplyError)
                {
                    co_return std::unexpected(ReplyFailureValue(ReplyError.error()));
                }
            }
            Req_ = RequestValue;
            Handshaken_ = true;
            co_return std::move(RequestValue);
        }

        [[nodiscard]] auto SendConnectReply(
            const ConnTransport<Memory> &Transport,
            ReplyCode Code) const -> Net::awaitable<ReplyResult<std::size_t>>
        {
            return SendReply(Transport, Code);
        }

        /**
         * @brief 写 BND 应答并报告真实传输进度。
         * @param Transport Conn 持有的传输借用至 completion。
         * @param Code 按值传入的 SOCKS5 回复码。
         * @param Bind 按值拥有的地址；wire 缓冲由本 owner 持有至 WriteSome 返回。
         * @return 成功字节数或协议码、Native cause 与 partial progress。
         * @note 调用者保持 Conn 存活并串行化同方向写；关闭仍由 association retirement owner 完成。
         */
        [[nodiscard]] auto SendAssocReply(
            ConnTransport<Memory> &Transport,
            ReplyCode Code,
            Address Bind) const -> Net::awaitable<ReplyResult<std::size_t>>
        {
            Reply ReplyValue;
            ReplyValue.Ver = Version;
            ReplyValue.Code = Code;
            if (Bind.Host.empty())
            {
                ReplyValue.Bind.Type = AddressType::Ipv4;
                ReplyValue.Bind.Host = "0.0.0.0";
                ReplyValue.Bind.Port = 0;
            }
            else
            {
                ReplyValue.Bind = std::move(Bind);
            }
            BuildReply(ReplyValue, TxWire_);
            if (TxWire_.empty())
            {
                co_return std::unexpected(
                    ReplyFailure{Error::BadAddress, {}, 0});
            }

            std::size_t Written = 0;
            while (Written < TxWire_.size())
            {
                const auto Remaining = TxWire_.size() - Written;
                const auto Buffer = std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(TxWire_.data() + Written), Remaining);
                const auto Result = co_await Transport.WriteSome(Buffer);
                const auto Progress = std::min(Result.Bytes, Remaining);
                Written += Progress;
                if (Result.Failure.Failed() || Result.Bytes == 0 || Result.Bytes > Remaining)
                {
                    auto Cause = Result.Failure;
                    if (!Cause.Failed()) Cause.Code = Preview::Fault::Code::IoError;
                    co_return std::unexpected(
                        ReplyFailure{Error::IoError, std::move(Cause), Written});
                }
            }
            co_return Written;
        }

    private:
        [[nodiscard]] auto SendMethodReply(
            const ConnTransport<Memory> &Transport,
            std::uint8_t Method) const -> Net::awaitable<ReplyResult<std::size_t>>
        {
            const std::array<std::uint8_t, 2> Wire{Version, Method};
            const auto Result = co_await Transport.SendBytes(Wire);
            if (Result.Failure.Failed())
            {
                co_return std::unexpected(ReplyFailure{
                    Error::IoError, Result.Failure, Result.Bytes});
            }
            co_return Result.Bytes;
        }

        [[nodiscard]] auto SendReply(
            const ConnTransport<Memory> &Transport,
            ReplyCode Code,
            const Address &Bind = {}) const -> Net::awaitable<ReplyResult<std::size_t>>
        {
            Reply ReplyValue;
            ReplyValue.Ver = Version;
            ReplyValue.Code = Code;
            if (Bind.Host.empty())
            {
                ReplyValue.Bind.Type = AddressType::Ipv4;
                ReplyValue.Bind.Host = "0.0.0.0";
                ReplyValue.Bind.Port = 0;
            }
            else
            {
                ReplyValue.Bind = Bind;
            }
            BuildReply(ReplyValue, TxWire_);
            if (TxWire_.empty())
            {
                co_return std::unexpected(ReplyFailure{Error::BadAddress, {}, 0});
            }
            const auto Result = co_await Transport.SendBytes(TxWire_);
            if (Result.Failure.Failed())
            {
                co_return std::unexpected(ReplyFailure{
                    Error::IoError, Result.Failure, Result.Bytes});
            }
            co_return Result.Bytes;
        }

        [[nodiscard]] auto ReadMessage(
            ConnTransport<Memory> &Transport,
            Message::Kind Kind)
            -> Net::awaitable<std::expected<Message, Preview::Fault::Failure>>
        {
            Parser ParserValue;
            ParserValue.Expect(Kind);
            const auto NeedMore = make_error_code(Error::NeedMore);
            while (!ParserValue.IsDone())
            {
                std::array<std::uint8_t, 1> Byte{};
                const auto Read = co_await Transport.ReadExact(std::span<std::uint8_t>(Byte));
                if (Read.Failure.Failed())
                {
                    co_return std::unexpected(Read.Failure);
                }
                if (Read.Bytes != Byte.size())
                    co_return std::unexpected(ProtocolFailure(Error::BadMessage));
                std::error_code ParseError;
                ParserValue.Put(Net::const_buffer(Byte.data(), Byte.size()), ParseError);
                if (ParseError && ParseError != NeedMore)
                {
                    co_return std::unexpected(ProtocolFailure(
                        static_cast<Error>(ParseError.value())));
                }
            }
            co_return ParserValue.Get();
        }

        [[nodiscard]] auto ReadReply(
            ConnTransport<Memory> &Transport)
            -> Net::awaitable<std::expected<Reply, Preview::Fault::Failure>>
        {
            std::array<std::uint8_t, 4> Head{};
            const auto HeadRead = co_await Transport.ReadExact(std::span<std::uint8_t>(Head));
            if (HeadRead.Failure.Failed())
            {
                co_return std::unexpected(HeadRead.Failure);
            }
            if (HeadRead.Bytes != Head.size())
                co_return std::unexpected(ProtocolFailure(Error::BadMessage));
            if (Head[0] != Version)
            {
                co_return std::unexpected(ProtocolFailure(Error::BadMagic));
            }
            if (Head[2] != 0)
            {
                co_return std::unexpected(ProtocolFailure(Error::BadMessage));
            }
            Reply Output;
            Output.Ver = Head[0];
            Output.Code = static_cast<ReplyCode>(Head[1]);
            Output.Bind.Type = static_cast<AddressType>(Head[3]);
            const auto AddressRead = co_await ReadAddress(Transport, Output.Bind);
            if (!AddressRead) co_return std::unexpected(AddressRead.error());
            co_return Output;
        }

        [[nodiscard]] static auto ReadAddress(
            ConnTransport<Memory> &Transport,
            Address &Output)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            if (Output.Type == AddressType::Ipv4)
            {
                std::array<std::uint8_t, 4> Bytes{};
                const auto Read = co_await Transport.ReadExact(Bytes);
                if (Read.Failure.Failed()) co_return std::unexpected(Read.Failure);
                if (Read.Bytes != Bytes.size())
                    co_return std::unexpected(ProtocolFailure(Error::BadMessage));
                Output.Host = boost::asio::ip::address_v4(Bytes).to_string();
            }
            else if (Output.Type == AddressType::Ipv6)
            {
                std::array<std::uint8_t, 16> Bytes{};
                const auto Read = co_await Transport.ReadExact(Bytes);
                if (Read.Failure.Failed()) co_return std::unexpected(Read.Failure);
                if (Read.Bytes != Bytes.size())
                    co_return std::unexpected(ProtocolFailure(Error::BadMessage));
                Output.Host = boost::asio::ip::address_v6(Bytes).to_string();
            }
            else if (Output.Type == AddressType::Domain)
            {
                std::array<std::uint8_t, 1> Length{};
                const auto LengthRead = co_await Transport.ReadExact(Length);
                if (LengthRead.Failure.Failed())
                    co_return std::unexpected(LengthRead.Failure);
                if (LengthRead.Bytes != Length.size() || Length[0] == 0U)
                    co_return std::unexpected(ProtocolFailure(Error::BadMessage));
                std::vector<std::uint8_t> Bytes(Length[0]);
                const auto Read = co_await Transport.ReadExact(Bytes);
                if (Read.Failure.Failed()) co_return std::unexpected(Read.Failure);
                if (Read.Bytes != Bytes.size())
                    co_return std::unexpected(ProtocolFailure(Error::BadMessage));
                Output.Host.assign(Bytes.begin(), Bytes.end());
            }
            else
            {
                co_return std::unexpected(ProtocolFailure(Error::BadMessage));
            }

            std::array<std::uint8_t, 2> Port{};
            const auto PortRead = co_await Transport.ReadExact(Port);
            if (PortRead.Failure.Failed())
            {
                co_return std::unexpected(PortRead.Failure);
            }
            if (PortRead.Bytes != Port.size())
                co_return std::unexpected(ProtocolFailure(Error::BadMessage));
            Output.Port = static_cast<std::uint16_t>(Port[0]) << 8 | Port[1];
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] static auto ProtocolFailure(const Error Value) noexcept
            -> Preview::Fault::Failure
        {
            return Preview::Protocol::Common::FailureFromProtocolError(Value);
        }

        [[nodiscard]] static auto FailureFromReplyCode(const ReplyCode Value) noexcept
            -> Preview::Fault::Failure
        {
            using Code = Preview::Fault::Code;
            switch (Value)
            {
            case ReplyCode::Success:
                return {Code::InvalidArgument};
            case ReplyCode::GeneralFailure:
                return {Code::BadGateway};
            case ReplyCode::NotAllowed:
                return {Code::Forbidden};
            case ReplyCode::NetworkUnreachable:
                return {Code::NetNoreply};
            case ReplyCode::HostUnreachable:
                return {Code::HostNoreply};
            case ReplyCode::ConnectionRefused:
                return {Code::ConnectionRefused};
            case ReplyCode::TtlExpired:
                return {Code::TtlExpired};
            case ReplyCode::CommandNotSupported:
                return {Code::UnsupportedCommand};
            case ReplyCode::AddressNotSupported:
                return {Code::UnsupportedAddress};
            }
            return {Code::BadMessage};
        }

        [[nodiscard]] static auto ReplyFailureValue(const ReplyFailure &Value) noexcept
            -> Preview::Fault::Failure
        {
            if (Value.Transport.Failed()) return Value.Transport;
            if (Value.Protocol != Error::None) return ProtocolFailure(Value.Protocol);
            return {Preview::Fault::Code::IoError};
        }

        Request Req_{};
        Address Bind_{};
        mutable typename Memory::template Buffer<std::uint8_t> TxWire_;
        bool Handshaken_{false};
    };

} // namespace Preview::Socks5
