/**
 * @file Auth.hpp
 * @brief TUIC exporter、credential 和 authenticator 认证 owner。
 * @details 认证帧使用 UUID 与 TLS exporter token；静态 typed Credential
 *          只作为 authenticator 的凭据视图，成功后的 AccountLease 由
 *          ConnSession 持有，并可转移给 admission。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <Prism/Account/Credential.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Tuic/Codec.hpp>
#include <Prism/Protocols/Tuic/Connection/Io.hpp>
#include <cstdint>

namespace Prism::Tuic::detail
{

    namespace Net = boost::asio;

    /** @brief Auth 帧校验状态与独立 uni stream terminal 的组合结果。 */
    struct AuthenticationReadResult final
    {
        Error Status{Error::None};
        std::optional<Prism::Fault::Failure> Terminal{};

        /** @brief 完整 EOF 是 Auth uni stream 的正常结束；其余失败转为协议错误。 */
        [[nodiscard]] auto EffectiveStatus() const noexcept -> Error
        {
            if (Terminal && Terminal->Code != Prism::Fault::Code::Eof)
            {
                switch (Terminal->Code)
                {
                case Prism::Fault::Code::Canceled: return Error::Canceled;
                case Prism::Fault::Code::Timeout: return Error::Timeout;
                default: return Error::IoError;
                }
            }
            return Status;
        }
    };

    /**
     * @struct ServerAuthenticationMaterial
     * @brief 服务端 TUIC uni stream 认证所需的会话材料。
     * @details Credential 持有跨认证挂起点的静态 typed 凭据；wire token 只用于
     *          当前 TLS exporter 校验，不作为账户目录凭据。
     */
    struct ServerAuthenticationMaterial final
    {
        KeyingMaterialExporter Exporter{};
        std::string ExporterContext{};
        std::shared_ptr<const Prism::Account::Credential> Credential{};
    };

    /**
     * @class ConnAuth
     * @brief TUIC 连接认证和 admission 身份 owner。
     * @tparam Memory 会话内存策略
     */
    template <Prism::Memory::Restrict Memory>
    class ConnAuth final
    {
    public:
        explicit ConnAuth(ConnSession<Memory> &Session) noexcept : Session_(Session)
        {
        }

        ConnAuth(const ConnAuth &) = delete;
        auto operator=(const ConnAuth &) -> ConnAuth & = delete;

        /**
         * @brief 在独立 uni stream 发送 TUIC v5 认证帧。
         * @param AuthStream 已打开的 uni stream
         * @param Exporter 当前 TLS 会话 exporter
         * @param Password exporter context
         * @return 错误码
         */
        [[nodiscard]] auto WriteAuthentication(
            SharedTransmission AuthStream,
            const KeyingMaterialExporter &Exporter,
            std::string_view Password) -> Net::awaitable<Error>
        {
            Session_.BeginClientAuthentication();
            if (!AuthStream || !Exporter)
            {
                co_return Error::Unsupported;
            }
            std::array<std::uint8_t, TokenLen> Token{};
            if (!Exporter(
                    std::span<std::uint8_t>(Token),
                    std::span<const std::uint8_t>(Session_.Uuid()),
                    Password))
            {
                co_return Error::KdfError;
            }
            const auto Wire = BuildAuthenticate(Session_.Uuid(), Token);
            if (co_await ConnIo<Memory>::SendBytes(
                    AuthStream, std::span<const std::uint8_t>(Wire)))
            {
                co_return Error::IoError;
            }
            (void)co_await AuthStream->WriteShutdown();
            Session_.SetAuthenticated(true);
            co_return Error::None;
        }

        /**
         * @brief 从独立 uni stream 校验 TUIC v5 认证帧。
         * @param AuthStream 收到认证帧的 uni stream
         * @param Material 当前 TLS exporter 与静态账户凭据
         * @return 认证状态与该 uni stream 的 terminal；完整 EOF 表示正常结束。
         */
        [[nodiscard]] auto ReadAuthentication(
            SharedTransmission AuthStream,
            ServerAuthenticationMaterial Material)
            -> Net::awaitable<AuthenticationReadResult>
        {
            Session_.BeginAuthentication();
            if (!AuthStream || !Material.Exporter)
            {
                co_return AuthenticationReadResult{Error::Unsupported, {}};
            }
            std::array<std::uint8_t, AuthenticateFrameLen> Wire{};
            const auto ReadResult = co_await ConnIo<Memory>::ReadExactFrom(
                AuthStream, std::span<std::uint8_t>(Wire));
            auto Terminal = ReadResult.Failure.Failed()
                ? std::optional<Prism::Fault::Failure>{ReadResult.Failure}
                : std::optional<Prism::Fault::Failure>{};
            if (ReadResult.Bytes != Wire.size())
            {
                const auto ReadError = ReadResult.Failure.Code == Prism::Fault::Code::Eof
                    ? Error::UnexpectedEof
                    : Error::IoError;
                co_return AuthenticationReadResult{ReadError, std::move(Terminal)};
            }
            AuthenticateFrame Frame{};
            std::size_t Consumed = 0;
            const auto ParseErr = ParseAuthenticate(Wire, Frame, Consumed);
            const std::string_view GotUuid(
                reinterpret_cast<const char *>(Frame.Uuid.data()), Frame.Uuid.size());
            const std::string_view ExpectedUuid(
                reinterpret_cast<const char *>(Session_.Uuid().data()), Session_.Uuid().size());
            const auto UuidMatches = Prism::ConstantTimeEqual(GotUuid, ExpectedUuid);
            if (ParseErr != Error::None || Consumed != Wire.size() || !UuidMatches)
            {
                co_return AuthenticationReadResult{Error::BadAuth, std::move(Terminal)};
            }

            const std::string_view GotToken(
                reinterpret_cast<const char *>(Frame.Token.data()), Frame.Token.size());
            std::array<std::uint8_t, TokenLen> Expected{};
            if (!Material.Exporter(
                    std::span<std::uint8_t>(Expected),
                    std::span<const std::uint8_t>(Session_.Uuid()),
                    Material.ExporterContext))
            {
                co_return AuthenticationReadResult{Error::KdfError, std::move(Terminal)};
            }
            const std::string_view ExpectedToken(
                reinterpret_cast<const char *>(Expected.data()), Expected.size());
            if (!Prism::ConstantTimeEqual(GotToken, ExpectedToken))
            {
                co_return AuthenticationReadResult{Error::BadAuth, std::move(Terminal)};
            }

            if (const auto *Authenticator = Session_.Authenticator())
            {
                if (!Material.Credential || !Material.Credential->IsValid())
                {
                    co_return AuthenticationReadResult{Error::BadAuth, std::move(Terminal)};
                }
                auto AuthenticationResult = Authenticator->Authenticate(
                    Prism::AuthenticationRequest{
                        .AccountId = {},
                        .Identity = {},
                        .Credential = Material.Credential->View(),
                        .Rate = {}});
                if (!AuthenticationResult || !AuthenticationResult->AccountId())
                {
                    co_return AuthenticationReadResult{Error::BadAuth, std::move(Terminal)};
                }
                auto Lease = std::move(*AuthenticationResult);
                const auto AccountId = Lease.AccountId();
                auto Identity = std::string(Lease.Identity());
                Session_.SetAuthenticationResult(
                    AccountId, std::move(Lease), std::move(Identity));
            }
            else
            {
                Session_.SetAuthenticated(true);
            }
            co_return AuthenticationReadResult{Error::None, std::move(Terminal)};
        }

        [[nodiscard]] auto TakeAuthLease() -> Prism::Account::AccountLease
        {
            return Session_.TakeAuthLease();
        }

        [[nodiscard]] auto AccountId() const noexcept -> Prism::AccountId
        {
            return Session_.AccountId();
        }

        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Session_.Identity();
        }

        /** @brief 将连接级认证结果转移到后续 bidi stream。 */
        auto MarkAuthenticated(
            Prism::AccountId AccountId = {},
            Prism::Account::AccountLease Lease = {},
            std::string Identity = {}) -> void
        {
            Session_.SetAuthenticationResult(
                AccountId, std::move(Lease), std::move(Identity));
        }

    private:
        ConnSession<Memory> &Session_;
    };

} // namespace Prism::Tuic::detail

namespace Prism::Tuic
{

    using AuthenticationReadResult = detail::AuthenticationReadResult;
    using ServerAuthenticationMaterial = detail::ServerAuthenticationMaterial;

} // namespace Prism::Tuic
