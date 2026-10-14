/**
 * @file ConnAuth.hpp
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
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Account/Credential.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Tuic/Codec.hpp>
#include <Preview/Protocols/Tuic/ConnIo.hpp>

namespace Preview::Tuic::detail
{

    namespace Net = boost::asio;

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
        std::shared_ptr<const Preview::Account::Credential> Credential{};
    };

    /**
     * @class ConnAuth
     * @brief TUIC 连接认证和 admission 身份 owner。
     * @tparam Memory 会话内存策略
     */
    template <Preview::Memory::Restrict Memory>
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
         * @return 错误码
         */
        [[nodiscard]] auto ReadAuthentication(
            SharedTransmission AuthStream,
            ServerAuthenticationMaterial Material) -> Net::awaitable<Error>
        {
            Session_.BeginAuthentication();
            if (!AuthStream || !Material.Exporter)
            {
                co_return Error::Unsupported;
            }
            std::array<std::uint8_t, AuthenticateFrameLen> Wire{};
            if (co_await ConnIo<Memory>::ReadExactFrom(
                    AuthStream, std::span<std::uint8_t>(Wire)))
            {
                co_return Error::UnexpectedEof;
            }
            AuthenticateFrame Frame{};
            std::size_t Consumed = 0;
            const auto ParseErr = ParseAuthenticate(Wire, Frame, Consumed);
            const std::string_view GotUuid(
                reinterpret_cast<const char *>(Frame.Uuid.data()), Frame.Uuid.size());
            const std::string_view ExpectedUuid(
                reinterpret_cast<const char *>(Session_.Uuid().data()), Session_.Uuid().size());
            const auto UuidMatches = Preview::ConstantTimeEqual(GotUuid, ExpectedUuid);
            if (ParseErr != Error::None || Consumed != Wire.size() || !UuidMatches)
            {
                co_return Error::BadAuth;
            }

            const std::string_view GotToken(
                reinterpret_cast<const char *>(Frame.Token.data()), Frame.Token.size());
            std::array<std::uint8_t, TokenLen> Expected{};
            if (!Material.Exporter(
                    std::span<std::uint8_t>(Expected),
                    std::span<const std::uint8_t>(Session_.Uuid()),
                    Material.ExporterContext))
            {
                co_return Error::KdfError;
            }
            const std::string_view ExpectedToken(
                reinterpret_cast<const char *>(Expected.data()), Expected.size());
            if (!Preview::ConstantTimeEqual(GotToken, ExpectedToken))
            {
                co_return Error::BadAuth;
            }

            if (const auto *Authenticator = Session_.Authenticator())
            {
                if (!Material.Credential || !Material.Credential->IsValid())
                {
                    co_return Error::BadAuth;
                }
                auto AuthenticationResult = Authenticator->Authenticate(
                    Preview::AuthenticationRequest{
                        .AccountId = {},
                        .Identity = {},
                        .Credential = Material.Credential->View(),
                        .Rate = {}});
                if (!AuthenticationResult || !AuthenticationResult->AccountId())
                {
                    co_return Error::BadAuth;
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
            co_return Error::None;
        }

        [[nodiscard]] auto TakeAuthLease() -> Preview::Account::AccountLease
        {
            return Session_.TakeAuthLease();
        }

        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId
        {
            return Session_.AccountId();
        }

        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Session_.Identity();
        }

        /** @brief 将连接级认证结果转移到后续 bidi stream。 */
        auto MarkAuthenticated(
            Preview::AccountId AccountId = {},
            Preview::Account::AccountLease Lease = {},
            std::string Identity = {}) -> void
        {
            Session_.SetAuthenticationResult(
                AccountId, std::move(Lease), std::move(Identity));
        }

    private:
        ConnSession<Memory> &Session_;
    };

} // namespace Preview::Tuic::detail

namespace Preview::Tuic
{

    using ServerAuthenticationMaterial = detail::ServerAuthenticationMaterial;

} // namespace Preview::Tuic
