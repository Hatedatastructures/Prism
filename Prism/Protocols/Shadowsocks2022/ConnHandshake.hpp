/**
 * @file ConnHandshake.hpp
 * @brief Shadowsocks 2022 客户端/服务端连接握手 owner。
 * @details 负责 salt、固定头和变长头的读写、时间窗校验、响应衔接，
 *          以及协议侧 Authenticator/AccountLease 的生命周期交接。
 */
#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Utility/Crypto/Random.hpp>
#include <Prism/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnRecord.hpp>
#include <Prism/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestCodec.hpp>

namespace Prism::Shadowsocks2022::detail
{

    namespace Net = boost::asio;
    namespace ss = Prism::Shadowsocks2022;

    /**
     * @brief SS2022 握手 owner。
     * @tparam Memory 会话内存策略
     * @details 该对象只借用会话和 record owner；认证产生的租约继续
     *          保存在 ConnSession 中，直到上层显式 TakeAuthLease()。
     */
    template <Prism::Memory::Restrict Memory>
    class ConnHandshake final
    {
    public:
        using Session = ConnSession<Memory>;
        using Record = ConnRecord<Memory>;

        ConnHandshake(Session &SessionValue, Record &RecordValue)
            : Session_(SessionValue), Record_(RecordValue)
        {
        }

        [[nodiscard]] auto WriteHandshake(
            Prism::SharedTransmission Upstream,
            const ss::Address &Target)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            Session_.SetUpstream(std::move(Upstream));
            std::array<std::uint8_t, 16> Salt{};
            if (!Prism::Crypto::FillRandom(std::span<std::uint8_t>(Salt)))
            {
                co_return ProtocolFailure(Error::IoError);
            }
            const auto Key = ss::SessionKey(Session_.Psk_, Salt, 16);

            std::random_device RandomDevice;
            const auto TimeSec = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
            const auto PaddingLength = static_cast<std::uint16_t>(1 + RandomDevice() % 16);
            const auto VariablePlain = ss::BuildVarHeader(Target, PaddingLength, {});
            const auto FixedPlain = ss::ParseFixedHeader(
                ss::HeaderTypeClient,
                TimeSec,
                static_cast<std::uint16_t>(VariablePlain.size()));
            ss::ChunkCodec Codec(Key);
            const auto FixedEncrypted = Codec.SealRaw(FixedPlain);
            const auto VariableEncrypted = Codec.SealRaw(VariablePlain);
            std::vector<std::uint8_t> Wire;
            Wire.reserve(Salt.size() + FixedEncrypted.size() + VariableEncrypted.size());
            Wire.insert(Wire.end(), Salt.begin(), Salt.end());
            Wire.insert(Wire.end(), FixedEncrypted.begin(), FixedEncrypted.end());
            Wire.insert(Wire.end(), VariableEncrypted.begin(), VariableEncrypted.end());
            const auto Written = co_await Record_.SendBytes(Wire);
            if (Written.Failed())
            {
                co_return Written;
            }

            std::array<std::uint8_t, 16> ServerSalt{};
            const auto SaltRead = co_await Record_.ReadExact(ServerSalt);
            if (SaltRead.Failure.Failed())
            {
                co_return SaltRead.Failure;
            }
            const auto ResponseKey = ss::SessionKey(Session_.Psk_, ServerSalt, 16);
            ss::ChunkCodec ResponseCodec(ResponseKey);
            std::array<std::uint8_t, ss::RespFixedHdrSize> ResponseEncrypted{};
            const auto HeaderRead = co_await Record_.ReadExact(ResponseEncrypted);
            if (HeaderRead.Failure.Failed())
            {
                co_return HeaderRead.Failure;
            }
            const auto ResponsePlain = ResponseCodec.OpenRaw(ResponseEncrypted);
            if (ResponsePlain.size() != ss::RespFixedHdrPlain ||
                ResponsePlain[0] != ss::HeaderTypeServer)
            {
                co_return ProtocolFailure(Error::BadAuth);
            }
            if (std::memcmp(ResponsePlain.data() + 9, Salt.data(), Salt.size()) != 0)
            {
                co_return ProtocolFailure(Error::BadAuth);
            }

            const auto ResponsePayloadLength =
                static_cast<std::size_t>(ResponsePlain[25]) << 8 | ResponsePlain[26];
            if (ResponsePayloadLength > 0)
            {
                auto PayloadEncrypted = Session_.Mem_.template MakeBuffer<std::uint8_t>(
                    ResponsePayloadLength + ss::AeadTagLen);
                const auto PayloadRead = co_await Record_.ReadExact(PayloadEncrypted);
                if (PayloadRead.Failure.Failed())
                {
                    co_return PayloadRead.Failure;
                }
                auto Payload = ResponseCodec.OpenRaw(PayloadEncrypted);
                if (Payload.empty())
                {
                    co_return ProtocolFailure(Error::BadAuth);
                }
                Session_.PlainRx_.assign(Payload.begin(), Payload.end());
                Session_.PlainOff_ = 0;
            }
            else
            {
                std::array<std::uint8_t, ss::AeadTagLen> EmptyBlock{};
                const auto EmptyRead = co_await Record_.ReadExact(EmptyBlock);
                if (EmptyRead.Failure.Failed())
                {
                    co_return EmptyRead.Failure;
                }
                std::vector<std::uint8_t> EmptyPlain;
                if (!ResponseCodec.OpenRaw(EmptyBlock, EmptyPlain))
                {
                    co_return ProtocolFailure(Error::BadAuth);
                }
            }

            Record_.ConfigureEncoder(std::move(Codec));
            Record_.ConfigureDecoder(std::move(ResponseCodec));
            std::memcpy(Session_.SessionKey_.data(), Key.data(), Session_.SessionKey_.size());
            Session_.Handshaken_ = true;
            co_return Prism::Fault::Failure{};
        }

        [[nodiscard]] auto ReadHandshake(Prism::SharedTransmission Upstream)
            -> Net::awaitable<std::expected<ss::Message, Prism::Fault::Failure>>
        {
            Session_.SetUpstream(std::move(Upstream));
            ss::Message Parsed;
            auto Request = co_await ReadRequest();
            if (!Request)
            {
                co_return std::unexpected(Request.error());
            }
            Parsed = std::move(*Request);

            if (Session_.AuthOwner_)
            {
                auto AuthenticationResult = Session_.AuthOwner_->Authenticate(
                    Prism::AuthenticationRequest{
                        .AccountId = {},
                        .Identity = {},
                        .Credential = Prism::Account::CredentialView{
                            Prism::Account::CredentialKind::Psk,
                            std::as_bytes(std::span<const std::uint8_t>(Session_.Psk_))},
                        .Rate = {}});
                if (!AuthenticationResult)
                {
                    co_return std::unexpected(AuthenticationResult.error());
                }
                Session_.AuthLease_ = std::move(*AuthenticationResult);
                Session_.AccountId_ = Session_.AuthLease_.AccountId();
                Session_.Identity_ = std::string(Session_.AuthLease_.Identity());
            }

            const auto Sent = co_await SendSuccess();
            if (Sent.Failed())
            {
                co_return std::unexpected(Sent);
            }
            Session_.Handshaken_ = true;
            Session_.Parsed_ = Parsed;
            Session_.PlainRx_.assign(
                reinterpret_cast<const std::uint8_t *>(Parsed.InitialPayload.data()),
                reinterpret_cast<const std::uint8_t *>(Parsed.InitialPayload.data()) +
                    Parsed.InitialPayload.size());
            Session_.PlainOff_ = 0;
            co_return Parsed;
        }

        [[nodiscard]] auto Parsed() const -> const ss::Message &
        {
            return Session_.Parsed_;
        }

        [[nodiscard]] auto TakeAuthLease() -> Prism::Account::AccountLease
        {
            return std::move(Session_.AuthLease_);
        }

        [[nodiscard]] auto AccountId() const noexcept -> Prism::AccountId
        {
            return Session_.AccountId_;
        }

        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Session_.Identity_;
        }

    private:
        [[nodiscard]] auto SendSuccess() -> Net::awaitable<Prism::Fault::Failure>
        {
            const auto TimeSec = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
            std::array<std::uint8_t, 16> ServerSalt{};
            if (!Prism::Crypto::FillRandom(std::span<std::uint8_t>(ServerSalt)))
            {
                co_return ProtocolFailure(Error::IoError);
            }
            const auto ResponseKey = ss::SessionKey(Session_.Psk_, ServerSalt, 16);
            std::array<std::uint8_t, ss::RespFixedHdrPlain> ResponsePlain{};
            ResponsePlain[0] = ss::HeaderTypeServer;
            for (std::size_t Index = 0; Index < 8; ++Index)
            {
                ResponsePlain[1 + Index] = static_cast<std::uint8_t>(
                    (TimeSec >> (56 - static_cast<unsigned>(Index) * 8)) & 0xFF);
            }
            std::memcpy(ResponsePlain.data() + 9,
                        Session_.ClientSalt_.data(),
                        Session_.ClientSalt_.size());
            ss::ChunkCodec ResponseCodec(ResponseKey);
            const auto ResponseEncrypted = ResponseCodec.SealRaw(ResponsePlain);
            const auto EmptyEncrypted = ResponseCodec.SealRaw({});
            std::vector<std::uint8_t> Wire;
            Wire.reserve(ServerSalt.size() + ResponseEncrypted.size() + EmptyEncrypted.size());
            Wire.insert(Wire.end(), ServerSalt.begin(), ServerSalt.end());
            Wire.insert(Wire.end(), ResponseEncrypted.begin(), ResponseEncrypted.end());
            Wire.insert(Wire.end(), EmptyEncrypted.begin(), EmptyEncrypted.end());
            const auto Written = co_await Record_.SendBytes(Wire);
            if (Written.Failed())
            {
                co_return Written;
            }
            Record_.ConfigureEncoder(std::move(ResponseCodec));
            co_return Prism::Fault::Failure{};
        }

        [[nodiscard]] auto ReadRequest()
            -> Net::awaitable<std::expected<ss::Message, Prism::Fault::Failure>>
        {
            std::array<std::uint8_t, 16> Salt{};
            const auto SaltRead = co_await Record_.ReadExact(Salt);
            if (SaltRead.Failure.Failed())
            {
                co_return std::unexpected(SaltRead.Failure);
            }
            ss::Parser RequestParser(Session_.Psk_);
            std::error_code ParseError;
            RequestParser.Put(Net::const_buffer(Salt.data(), Salt.size()), ParseError);
            const auto NeedMore = make_error_code(Error::NeedMore);
            if (ParseError && ParseError != NeedMore)
            {
                co_return std::unexpected(ProtocolFailure(Error::BadAuth));
            }
            while (!RequestParser.IsDone())
            {
                std::array<std::uint8_t, 1> Byte{};
                const auto ByteRead = co_await Record_.ReadExact(Byte);
                if (ByteRead.Failure.Failed())
                {
                    co_return std::unexpected(ByteRead.Failure);
                }
                ParseError.clear();
                RequestParser.Put(Net::const_buffer(Byte.data(), Byte.size()), ParseError);
                if (ParseError && ParseError != NeedMore)
                {
                    co_return std::unexpected(ProtocolFailure(Error::BadAuth));
                }
            }

            const auto Now = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
            const auto Timestamp = RequestParser.TimeSec();
            const auto Difference = Now >= Timestamp ? Now - Timestamp : Timestamp - Now;
            if (Difference > Session_.TimeWindow_)
            {
                co_return std::unexpected(ProtocolFailure(Error::BadAuth));
            }

            auto Output = RequestParser.Get();
            const auto Key = ss::SessionKey(Session_.Psk_, Salt, 16);
            std::memcpy(Session_.ClientSalt_.data(), Salt.data(), Salt.size());
            std::memcpy(Session_.SessionKey_.data(), Key.data(), Key.size());
            Record_.ConfigureDecoder(ss::ChunkCodec(Key, 2));
            co_return Output;
        }

        [[nodiscard]] static auto ProtocolFailure(const Error Value) noexcept
            -> Prism::Fault::Failure
        {
            return {Prism::Fault::Detail::MapProtocolCategoryValue(static_cast<int>(Value)), {}};
        }

        Session &Session_;
        Record &Record_;
    };

} // namespace Prism::Shadowsocks2022::detail
