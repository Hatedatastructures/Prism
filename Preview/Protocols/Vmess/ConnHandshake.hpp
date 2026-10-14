/**
 * @file ConnHandshake.hpp
 * @brief VMess 客户端/服务端认证握手 owner。
 * @details 负责认证头、请求头和响应头的状态机，以及握手后的账户租约
 *          归属；底层精确读写和数据 chunk 编解码由专用 owner 提供。
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/ByteSpan.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Common/ExactIo.hpp>
#include <Preview/Protocols/Vmess/Auth.hpp>
#include <Preview/Protocols/Vmess/ConnChunk.hpp>
#include <Preview/Protocols/Vmess/ConnIo.hpp>
#include <Preview/Protocols/Vmess/RequestCodec.hpp>
#include <Preview/Protocols/Vmess/ResponseCodec.hpp>

namespace Preview::Vmess::detail
{

    namespace Net = boost::asio;

    /** @brief 客户端握手期间保留的随机量和响应方向密钥。 */
    struct ClientHandshakeState final
    {
        std::array<std::uint8_t, 16> Iv{};
        std::array<std::uint8_t, 16> Key{};
        std::array<std::uint8_t, 4> AuthRandom{};
        std::array<std::uint8_t, 16> AuthId{};
        std::array<std::uint8_t, 16> ResponseKey{};
        std::array<std::uint8_t, 16> ResponseNonce{};
        std::uint8_t Version{0};
    };

    /**
     * @brief VMess 认证和请求/响应头握手 owner。
     * @tparam Memory 会话内存策略
     * @details 只改变握手阶段的 session 状态，认证租约和身份始终留在
     *          ConnSession，避免握手对象析构导致账户所有权丢失。
     */
    template <Preview::Memory::Restrict Memory>
    class ConnHandshake final
    {
    public:
        using Session = ConnSession<Memory>;

        explicit ConnHandshake(
            Session &SessionValue,
            ConnIo<Memory> &IoValue,
            ConnChunk<Memory> &ChunkValue)
            : Session_(SessionValue), Io_(IoValue), Chunk_(ChunkValue)
        {
        }

        [[nodiscard]] auto WriteHandshake(
            Preview::SharedTransmission Upstream,
            const Address &Target,
            std::uint8_t CommandValue = static_cast<std::uint8_t>(Command::Tcp))
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            Session_.Reset(std::move(Upstream), false);
            Chunk_.Reset();

            ClientHandshakeState State;
            if (!FillRandomBytes(State.Iv) || !FillRandomBytes(State.Key) ||
                !FillRandomBytes(State.AuthRandom))
            {
                co_return std::unexpected(Preview::Protocol::Common::FailureFromProtocolError(Error::IoError));
            }
            std::array<std::uint8_t, 2> MetadataRandom{};
            if (!FillRandomBytes(MetadataRandom))
            {
                co_return std::unexpected(Preview::Protocol::Common::FailureFromProtocolError(Error::IoError));
            }
            State.Version = MetadataRandom[0];
            const auto PaddingLength = static_cast<std::uint8_t>(MetadataRandom[1] % 16);
            const auto TimeSec = std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count();

            RequestHeader RequestValue;
            RequestValue.Version = ProtocolVersion;
            RequestValue.Cmd = CommandValue;
            RequestValue.opt = static_cast<std::uint8_t>(Option::ChunkStream) |
                               static_cast<std::uint8_t>(Option::ChunkMasking);
            RequestValue.sec = Security::Aes128Gcm;
            RequestValue.Target = Target;
            const auto Plain = BuildRequestHeader(
                RequestValue,
                RequestMeta{State.Iv, State.Key, State.Version, PaddingLength});
            const auto CmdKey = CmdKeyFromUuid(Session_.Uuid_);
            const auto Sealed = SealAuthHeader(
                CmdKey,
                AuthHeaderInput{Plain, TimeSec, State.AuthRandom},
                Session_.Random_);
            State.AuthId = CreateAuthId(CmdKey, TimeSec, State.AuthRandom);
            if (Sealed.empty())
            {
                co_return std::unexpected(Preview::Protocol::Common::FailureFromProtocolError(Error::CryptoError));
            }
            const auto Written = co_await Io_.WriteAllIo(Sealed);
            if (Written.Failure.Failed())
            {
                co_return std::unexpected(Written.Failure);
            }

            const auto ResponseResult = co_await ReadClientResponse(State);
            if (!ResponseResult)
            {
                co_return std::unexpected(ResponseResult.error());
            }

            ChunkKeys Keys;
            Keys.EncryptKey = State.Key;
            Keys.EncryptNonce = State.Iv;
            Keys.DecryptKey = State.ResponseKey;
            Keys.DecryptNonce = State.ResponseNonce;
            Keys.Options = RequestValue.opt;
            Chunk_.Configure(std::move(Keys));
            Session_.Handshaken_ = true;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] auto ReadHandshake(
            Preview::SharedTransmission Upstream,
            bool EnableUdp = true,
            bool EnableMux = true)
            -> Net::awaitable<std::expected<Message, Preview::Fault::Failure>>
        {
            Session_.Reset(std::move(Upstream), true);
            Chunk_.Reset();

            Message RequestValue;
            auto RequestResult = co_await ReadRequest(RequestValue);
            if (!RequestResult)
            {
                co_return std::unexpected(RequestResult.error());
            }

            const auto Cmd = static_cast<Command>(RequestValue.Cmd);
            if (Cmd != Command::Tcp && Cmd != Command::Udp && Cmd != Command::Mux)
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::BadMessage));
            }
            if (Cmd == Command::Mux && !EnableMux)
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::Unsupported));
            }
            if (Cmd == Command::Udp && !EnableUdp)
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::Unsupported));
            }

            const auto ResponseResult = co_await SendSuccess(RequestValue);
            if (!ResponseResult)
            {
                co_return std::unexpected(ResponseResult.error());
            }

            const auto ResponseBodyKey = detail::Sha256(RequestValue.RequestKey);
            const auto ResponseBodyNonce = detail::Sha256(RequestValue.RequestNonce);
            std::array<std::uint8_t, 16> ResponseKey{};
            std::array<std::uint8_t, 16> ResponseNonce{};
            std::memcpy(ResponseKey.data(), ResponseBodyKey.data(), ResponseKey.size());
            std::memcpy(ResponseNonce.data(), ResponseBodyNonce.data(), ResponseNonce.size());

            ChunkKeys Keys;
            Keys.EncryptKey = ResponseKey;
            Keys.EncryptNonce = ResponseNonce;
            Keys.DecryptKey = RequestValue.RequestKey;
            Keys.DecryptNonce = RequestValue.RequestNonce;
            Keys.Options = RequestValue.Option;
            Chunk_.Configure(std::move(Keys));
            Session_.Handshaken_ = true;
            Session_.Parsed_ = RequestValue;
            co_return std::move(RequestValue);
        }

        [[nodiscard]] auto Parsed() const -> const Message &
        {
            return Session_.Parsed_;
        }

        [[nodiscard]] auto TakeAuthLease() -> Preview::Account::AccountLease
        {
            return std::move(Session_.AuthLease_);
        }

        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId
        {
            return Session_.AccountId_;
        }

        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Session_.Identity_;
        }

    private:
        [[nodiscard]] auto ReadClientResponse(ClientHandshakeState &State)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            std::array<std::uint8_t, 18> LengthEncrypted{};
            const auto LengthRead = co_await Io_.ReadExactIo(LengthEncrypted);
            if (LengthRead.Failure.Failed())
            {
                co_return std::unexpected(LengthRead.Failure);
            }

            const auto ResponseBodyKey = detail::Sha256(State.Key);
            const auto ResponseBodyNonce = detail::Sha256(State.Iv);
            std::array<std::uint8_t, 16> ResponseKey16{};
            std::array<std::uint8_t, 16> ResponseNonce16{};
            std::memcpy(ResponseKey16.data(), ResponseBodyKey.data(), ResponseKey16.size());
            std::memcpy(ResponseNonce16.data(), ResponseBodyNonce.data(), ResponseNonce16.size());

            const auto LengthKeyPath = Kdf(ResponseKey16, KdfRespLenKey);
            const auto LengthNoncePath = Kdf(ResponseNonce16, KdfRespLenIv);
            std::array<std::uint8_t, 16> LengthKey{};
            std::array<std::uint8_t, 12> LengthNonce{};
            std::memcpy(LengthKey.data(), LengthKeyPath.data(), LengthKey.size());
            std::memcpy(LengthNonce.data(), LengthNoncePath.data(), LengthNonce.size());
            const auto LengthPlain = detail::AesGcmOpen(
                detail::OpenInput{LengthKey, LengthNonce, LengthEncrypted, {}});
            if (LengthPlain.size() != 2)
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::BadAuth));
            }
            const auto ResponseLength = static_cast<std::size_t>(LengthPlain[0]) << 8 |
                                         LengthPlain[1];
            if (ResponseLength > 0xFFFF - 16)
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::BadLength));
            }

            std::vector<std::uint8_t> ResponseEncrypted(ResponseLength + 16);
            const auto ResponseRead = co_await Io_.ReadExactIo(ResponseEncrypted);
            if (ResponseRead.Failure.Failed())
            {
                co_return std::unexpected(ResponseRead.Failure);
            }
            const auto ResponseKeyPath = Kdf(ResponseKey16, KdfRespKey);
            const auto ResponseNoncePath = Kdf(ResponseNonce16, KdfRespIv);
            std::array<std::uint8_t, 16> HeaderKey{};
            std::array<std::uint8_t, 12> HeaderNonce{};
            std::memcpy(HeaderKey.data(), ResponseKeyPath.data(), HeaderKey.size());
            std::memcpy(HeaderNonce.data(), ResponseNoncePath.data(), HeaderNonce.size());
            ResponseHeader ResponseValue;
            if (OpenResponseHeader(
                    HeaderKey,
                    RespHeaderParseInput{HeaderNonce, ResponseEncrypted},
                    ResponseValue) != Error::None)
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::BadAuth));
            }
            if (ResponseValue.Version != State.Version)
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::BadAuth));
            }
            State.ResponseKey = ResponseKey16;
            State.ResponseNonce = ResponseNonce16;
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] auto ReadRequest(Message &Output)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            Parser RequestParser(Session_.Uuid_);
            std::error_code ParseError;
            std::array<std::uint8_t, 42> Prefix{};
            const auto PrefixRead = co_await Io_.ReadExactIo(Prefix);
            if (PrefixRead.Failure.Failed())
            {
                co_return std::unexpected(PrefixRead.Failure);
            }
            RequestParser.Put(Net::const_buffer(Prefix.data(), Prefix.size()), ParseError);
            const auto NeedMore = make_error_code(Error::NeedMore);
            if (ParseError && ParseError != NeedMore)
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::BadAuth));
            }
            while (!RequestParser.IsDone())
            {
                std::array<std::uint8_t, 1> Byte{};
                const auto ByteRead = co_await Io_.ReadExactIo(Byte);
                if (ByteRead.Failure.Failed())
                {
                    co_return std::unexpected(ByteRead.Failure);
                }
                ParseError.clear();
                RequestParser.Put(Net::const_buffer(Byte.data(), Byte.size()), ParseError);
                if (ParseError && ParseError != NeedMore)
                {
                    co_return std::unexpected(
                        Preview::Protocol::Common::FailureFromProtocolError(Error::BadAuth));
                }
            }

            Output = RequestParser.Get();
            std::memcpy(Session_.AuthId_.data(), Output.AuthId.data(), Session_.AuthId_.size());
            const std::string_view GotUuid(
                reinterpret_cast<const char *>(Output.uuid.data()), Output.uuid.size());
            const std::string_view ExpectedUuid(
                reinterpret_cast<const char *>(Session_.Uuid_.data()), Session_.Uuid_.size());
            if (!Preview::ConstantTimeEqual(GotUuid, ExpectedUuid))
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::BadAuth));
            }
            if (const auto *Authenticator = Session_.Authenticator())
            {
                auto AuthenticationResult = Authenticator->Authenticate(
                    Preview::AuthenticationRequest{
                        .AccountId = {},
                        .Identity = {},
                        .Credential = Preview::Account::CredentialView{
                            Preview::Account::CredentialKind::Uuid,
                            std::as_bytes(std::span<const std::uint8_t>(Output.uuid))},
                        .Rate = {}});
                if (!AuthenticationResult)
                {
                    co_return std::unexpected(
                        Preview::Protocol::Common::FailureFromProtocolError(Error::BadAuth));
                }
                Session_.AuthLease_ = std::move(*AuthenticationResult);
                Session_.AccountId_ = Session_.AuthLease_.AccountId();
                Session_.Identity_ = std::string(Session_.AuthLease_.Identity());
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] auto SendSuccess(const Message &RequestValue) const
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            const auto ResponseBodyKey = detail::Sha256(RequestValue.RequestKey);
            const auto ResponseBodyNonce = detail::Sha256(RequestValue.RequestNonce);
            std::array<std::uint8_t, 16> ResponseKey16{};
            std::array<std::uint8_t, 16> ResponseNonce16{};
            std::memcpy(ResponseKey16.data(), ResponseBodyKey.data(), ResponseKey16.size());
            std::memcpy(ResponseNonce16.data(), ResponseBodyNonce.data(), ResponseNonce16.size());

            const std::array<std::uint8_t, 4> ResponsePlain{
                RequestValue.RespHeader,
                RequestValue.Option,
                0,
                0};
            const auto ResponseKeyPath = Kdf(ResponseKey16, KdfRespKey);
            const auto ResponseNoncePath = Kdf(ResponseNonce16, KdfRespIv);
            std::array<std::uint8_t, 16> HeaderKey{};
            std::array<std::uint8_t, 12> HeaderNonce{};
            std::memcpy(HeaderKey.data(), ResponseKeyPath.data(), HeaderKey.size());
            std::memcpy(HeaderNonce.data(), ResponseNoncePath.data(), HeaderNonce.size());
            const auto ResponseEncrypted = SealResponseHeader(
                HeaderKey,
                RespHeaderInput{HeaderNonce, ResponsePlain});
            if (ResponseEncrypted.size() != 20)
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::CryptoError));
            }

            const auto LengthKeyPath = Kdf(ResponseKey16, KdfRespLenKey);
            const auto LengthNoncePath = Kdf(ResponseNonce16, KdfRespLenIv);
            std::array<std::uint8_t, 16> LengthKey{};
            std::array<std::uint8_t, 12> LengthNonce{};
            std::memcpy(LengthKey.data(), LengthKeyPath.data(), LengthKey.size());
            std::memcpy(LengthNonce.data(), LengthNoncePath.data(), LengthNonce.size());
            const std::array<std::uint8_t, 2> ResponseLengthPlain{0, 4};
            const auto LengthEncrypted = detail::AesGcmSeal(
                detail::SealInput{LengthKey, LengthNonce, ResponseLengthPlain, {}});
            if (LengthEncrypted.size() != 18)
            {
                co_return std::unexpected(
                    Preview::Protocol::Common::FailureFromProtocolError(Error::CryptoError));
            }

            std::vector<std::uint8_t> Response;
            Response.reserve(LengthEncrypted.size() + ResponseEncrypted.size());
            Response.insert(Response.end(), LengthEncrypted.begin(), LengthEncrypted.end());
            Response.insert(Response.end(), ResponseEncrypted.begin(), ResponseEncrypted.end());
            const auto Written = co_await Io_.WriteAllIo(Response);
            if (Written.Failure.Failed())
            {
                co_return std::unexpected(Written.Failure);
            }
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] auto FillRandomBytes(std::span<std::uint8_t> Data) -> bool
        {
            if (Session_.Random_)
            {
                return Preview::Crypto::FillRandom(Data, Session_.Random_).has_value();
            }
            return Preview::Crypto::FillRandom(Data).has_value();
        }

        Session &Session_;
        ConnIo<Memory> &Io_;
        ConnChunk<Memory> &Chunk_;
    };

} // namespace Preview::Vmess::detail
