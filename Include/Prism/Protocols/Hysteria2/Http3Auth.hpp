/**
 * @file Http3Auth.hpp
 * @brief Hysteria2-owned HTTP/3 authentication wire and session contract.
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <cstddef>
#include <string>
#include <string_view>
#include <span>
#include <thread>
#include <variant>

#include <Prism/Account/Lease.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Http3/Auth.hpp>

namespace Prism::Hysteria2
{

    inline constexpr std::uint64_t AuthFrameHeaders = 0x01;

    struct WireAuthRequest final
    {
        std::string Method;
        std::string Authority;
        std::string Path;
        std::string Credential;
        std::uint64_t ReceiveRate{0};
    };

    [[nodiscard]] auto WriteAuthFrameVarint(
        std::span<std::byte> Output,
        std::size_t &Offset,
        std::uint64_t Value) -> bool;

    [[nodiscard]] auto ParseAuthRequestWire(
        std::span<const std::uint8_t> Data,
        WireAuthRequest &Output,
        Prism::Memory::ResourcePointer Resource) -> bool;

    enum class AuthError : std::uint8_t
    {
        InvalidRequest,
        AuthenticatorUnavailable,
        Unauthorized,
        AlreadyAuthenticated,
        StreamQuota,
        Closed,
        InvalidResponse,
    };

    struct ClientAuthOptions final
    {
        std::string Authority{"hysteria"};
        std::string Password;
        std::uint64_t ReceiveRate{0};
        std::string Padding;
    };

    /** @brief 服务端要求客户端自行拥塞控制；不得折叠为数值接收速率。 */
    struct AutomaticReceiveRate final
    {
    };

    struct AuthResponse final
    {
        bool UdpEnabled{false};
        /** @brief 数值速率或 typed auto 标记，响应 padding 不属于业务结果。 */
        std::variant<std::uint64_t, AutomaticReceiveRate> ReceiveRate{std::uint64_t{0}};
    };

    /**
     * @brief 构造客户端 HTTP/3 认证请求。
     * @param Options 按值接管认证材料；空 Padding 不写可选 header。
     * @return 拥有 header arena 的请求；无网络 I/O、取消或关闭动作。
     * @note 调用方负责后续 HTTP/3 stream 的 executor、半关闭和最终关闭。
     */
    [[nodiscard]] auto BuildAuthRequest(ClientAuthOptions Options) -> Prism::Http3::RequestHead;

    [[nodiscard]] auto BuildAuthFailureResponse(
        std::int64_t StreamId,
        AuthError Error) -> Prism::Http3::ResponseHead;

    /**
     * @brief 解析 status 233 的认证响应。
     * @param Response 按值接管响应 header owner；padding 内容只校验重复，不保存。
     * @return typed UDP/rate 结果或 InvalidResponse；无网络 I/O、取消或关闭动作。
     * @note 调用方负责认证后连接的 executor、半关闭和最终关闭。
     */
    [[nodiscard]] auto ParseAuthResponse(Prism::Http3::ResponseHead Response)
        -> std::expected<AuthResponse, AuthError>;

    struct Http3AuthSessionOptions final
    {
        boost::asio::any_io_executor Executor{};
        Prism::SharedAuthenticator Authenticator{};
    };

    /**
     * @class Http3AuthSession
     * @brief One authenticated Hysteria2 connection's owner.
     * @details The successful AuthenticationResult, including AccountLease,
     * remains here until Close() runs on Executor. After Close the object may
     * be destroyed by any thread.
     */
    class Http3AuthSession final
    {
    public:
        explicit Http3AuthSession(Http3AuthSessionOptions Options);

        ~Http3AuthSession() noexcept;

        Http3AuthSession(const Http3AuthSession &) = delete;
        auto operator=(const Http3AuthSession &) -> Http3AuthSession & = delete;

        [[nodiscard]] auto HandleRequest(Prism::Http3::RequestEvent Request)
            -> std::expected<Prism::Http3::ResponseHead, AuthError>;

        /** @brief 在 Options.Executor 上调用，幂等释放连接租约。 */
        auto Close() noexcept -> void;

        [[nodiscard]] auto AccountId() const noexcept -> Prism::AccountId
        {
            if (!Result_) { return {}; }
            return Result_->AccountId();
        }

        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            if (!Result_) { return {}; }
            return Result_->Identity();
        }

        [[nodiscard]] auto Authenticated() const noexcept -> bool
        {
            return static_cast<bool>(Result_) && static_cast<bool>(*Result_);
        }

        [[nodiscard]] auto AcquireStream()
            -> std::expected<Prism::Account::StreamLease, AuthError>;

        [[nodiscard]] auto Closed() const noexcept -> bool
        {
            return Closed_;
        }

    private:
        auto BindOwnerThread() noexcept -> void;

        Http3AuthSessionOptions Options_;
        Prism::AuthenticationResult Result_{};
        bool Closed_{false};
        std::thread::id OwnerThread_{};
    };


} // namespace Prism::Hysteria2
