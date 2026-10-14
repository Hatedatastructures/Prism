/**
 * @file Http3Auth.hpp
 * @brief Hysteria2-owned HTTP/3 authentication wire and session contract.
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>

#include <cassert>
#include <cstdint>
#include <charconv>
#include <limits>
#include <expected>
#include <memory>
#include <cstddef>
#include <string>
#include <string_view>
#include <span>
#include <thread>
#include <utility>
#include <variant>

#include <Preview/Account/Lease.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Protocols/Http3/Auth.hpp>

namespace Preview::Hysteria2
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
        Preview::Memory::ResourcePointer Resource) -> bool;

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
    [[nodiscard]] auto BuildAuthRequest(ClientAuthOptions Options) -> Preview::Http3::RequestHead;

    [[nodiscard]] auto BuildAuthFailureResponse(
        std::int64_t StreamId,
        AuthError Error) -> Preview::Http3::ResponseHead;

    /**
     * @brief 解析 status 233 的认证响应。
     * @param Response 按值接管响应 header owner；padding 内容只校验重复，不保存。
     * @return typed UDP/rate 结果或 InvalidResponse；无网络 I/O、取消或关闭动作。
     * @note 调用方负责认证后连接的 executor、半关闭和最终关闭。
     */
    [[nodiscard]] auto ParseAuthResponse(Preview::Http3::ResponseHead Response)
        -> std::expected<AuthResponse, AuthError>;

    struct Http3AuthSessionOptions final
    {
        boost::asio::any_io_executor Executor{};
        Preview::SharedAuthenticator Authenticator{};
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
        explicit Http3AuthSession(Http3AuthSessionOptions Options)
            : Options_(std::move(Options))
        {
        }

        ~Http3AuthSession() noexcept
        {
            assert(Closed_ || OwnerThread_ == std::thread::id{} ||
                   OwnerThread_ == std::this_thread::get_id());
        }

        Http3AuthSession(const Http3AuthSession &) = delete;
        auto operator=(const Http3AuthSession &) -> Http3AuthSession & = delete;

        [[nodiscard]] auto HandleRequest(Preview::Http3::RequestEvent Request)
            -> std::expected<Preview::Http3::ResponseHead, AuthError>;

        /** @brief 在 Options.Executor 上调用，幂等释放连接租约。 */
        auto Close() noexcept -> void;

        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId
        {
            if (!Result_) { return {}; }
            return Result_->AccountId();
        }

        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            if (!Result_) { return {}; }
            return Result_->DisplayIdentity();
        }

        [[nodiscard]] auto Authenticated() const noexcept -> bool
        {
            return static_cast<bool>(Result_) && static_cast<bool>(*Result_);
        }

        [[nodiscard]] auto AcquireStream()
            -> std::expected<Preview::Account::StreamLease, AuthError>;

        [[nodiscard]] auto Closed() const noexcept -> bool
        {
            return Closed_;
        }

    private:
        auto BindOwnerThread() noexcept -> void
        {
            if (OwnerThread_ == std::thread::id{})
            {
                OwnerThread_ = std::this_thread::get_id();
            }
            assert(OwnerThread_ == std::this_thread::get_id());
        }

        Http3AuthSessionOptions Options_;
        Preview::AuthenticationResult Result_{};
        bool Closed_{false};
        std::thread::id OwnerThread_{};
    };


    namespace
    {

        auto AddHeader(
            Preview::Http3::HeaderBlock &Headers,
            std::string_view Name,
            std::string Value) -> void
        {
            Headers.Fields.push_back({std::string(Name), std::move(Value)});
        }

        [[nodiscard]] auto ParseUnsigned(std::string_view Value, std::uint64_t &Output) -> bool
        {
            if (Value.empty())
            {
                return false;
            }
            const auto Result = std::from_chars(Value.data(), Value.data() + Value.size(), Output);
            return Result.ec == std::errc{} && Result.ptr == Value.data() + Value.size();
        }

    } // namespace

    inline auto WriteAuthFrameVarint(
        std::span<std::byte> Output,
        std::size_t &Offset,
        const std::uint64_t Value) -> bool
    {
        std::size_t Width = 1;
        std::uint8_t Prefix = 0;
        if (Value <= 0x3FU)
        {
            Width = 1;
        }
        else if (Value <= 0x3FFFU)
        {
            Width = 2;
            Prefix = 0x40U;
        }
        else if (Value <= 0x3FFFFFFFU)
        {
            Width = 4;
            Prefix = 0x80U;
        }
        else if (Value <= 0x3FFFFFFFFFFFFFFFULL)
        {
            Width = 8;
            Prefix = 0xC0U;
        }
        else
        {
            return false;
        }
        if (Offset > Output.size() || Width > Output.size() - Offset)
        {
            return false;
        }
        for (std::size_t Index = 0; Index < Width; ++Index)
        {
            const auto Shift = 8U * static_cast<unsigned>(Width - 1U - Index);
            auto Byte = static_cast<std::uint8_t>((Value >> Shift) & 0xFFU);
            if (Index == 0)
            {
                Byte = static_cast<std::uint8_t>(Byte | Prefix);
            }
            Output[Offset++] = static_cast<std::byte>(Byte);
        }
        return true;
    }

    inline auto ParseAuthRequestWire(
        const std::span<const std::uint8_t> Data,
        WireAuthRequest &Output,
        const Preview::Memory::ResourcePointer Resource) -> bool
    {
        Output = {};
        auto Fields = Preview::Http3::Qpack::DecodeHeaderBlock(Data, Resource);
        std::size_t MethodCount = 0;
        std::size_t AuthorityCount = 0;
        std::size_t PathCount = 0;
        std::size_t SchemeCount = 0;
        std::size_t CredentialCount = 0;
        std::size_t RateCount = 0;
        bool RegularFieldSeen = false;
        for (const auto &Field : Fields)
        {
            const std::string_view Name{Field.Name.data(), Field.Name.size()};
            const std::string_view Value{Field.value.data(), Field.value.size()};
            if (Name.empty())
            {
                return false;
            }
            if (Name.front() == ':')
            {
                if (RegularFieldSeen ||
                    (Name != ":method" && Name != ":authority" &&
                     Name != ":path" && Name != ":scheme"))
                {
                    return false;
                }
            }
            else
            {
                RegularFieldSeen = true;
            }
            if (Name == ":method")
            {
                ++MethodCount;
                Output.Method.assign(Value);
            }
            else if (Name == ":authority")
            {
                ++AuthorityCount;
                Output.Authority.assign(Value);
            }
            else if (Name == ":path")
            {
                ++PathCount;
                Output.Path.assign(Value);
            }
            else if (Name == ":scheme")
            {
                ++SchemeCount;
                if (Value != "https")
                {
                    return false;
                }
            }
            else if (Name == "hysteria-auth")
            {
                ++CredentialCount;
                Output.Credential.assign(Value);
            }
            else if (Name == "hysteria-cc-rx")
            {
                ++RateCount;
                const auto Parsed = std::from_chars(
                    Value.data(), Value.data() + Value.size(), Output.ReceiveRate);
                if (Parsed.ec != std::errc{} || Parsed.ptr != Value.data() + Value.size())
                {
                    return false;
                }
            }
        }
        return MethodCount == 1 && AuthorityCount == 1 && PathCount == 1 &&
               SchemeCount == 1 && CredentialCount == 1 && RateCount <= 1 &&
               Output.Method == "POST" && Output.Path == "/auth" &&
               !Output.Credential.empty();
    }

    inline auto BuildAuthRequest(ClientAuthOptions Options) -> Preview::Http3::RequestHead
    {
        auto Owner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::HeaderBlock Headers(Owner);
        AddHeader(Headers, ":method", "POST");
        AddHeader(Headers, ":scheme", "https");
        AddHeader(Headers, ":authority", std::move(Options.Authority));
        AddHeader(Headers, ":path", "/auth");
        AddHeader(Headers, "hysteria-auth", std::move(Options.Password));
        AddHeader(Headers, "hysteria-cc-rx", std::to_string(Options.ReceiveRate));
        if (!Options.Padding.empty())
        {
            AddHeader(Headers, "hysteria-padding", std::move(Options.Padding));
        }
        AddHeader(Headers, "content-length", "0");
        AddHeader(Headers, "accept-encoding", "gzip");
        AddHeader(Headers, "user-agent", "Go-http-client/3.0");
        return Preview::Http3::RequestHead{std::move(Headers), true};
    }

    inline auto ParseAuthResponse(Preview::Http3::ResponseHead Response)
        -> std::expected<AuthResponse, AuthError>
    {
        if (Response.Status != 233)
        {
            return std::unexpected(AuthError::InvalidResponse);
        }
        AuthResponse Result;
        std::string_view Udp;
        std::string_view ReceiveRate;
        std::size_t UdpCount = 0;
        std::size_t ReceiveRateCount = 0;
        std::size_t PaddingCount = 0;
        for (const auto &Field : Response.Headers.Fields)
        {
            const std::string_view Name{Field.Name.data(), Field.Name.size()};
            const std::string_view Value{Field.value.data(), Field.value.size()};
            if (Name == "hysteria-udp")
            {
                Udp = Value;
                ++UdpCount;
            }
            else if (Name == "hysteria-cc-rx")
            {
                ReceiveRate = Value;
                ++ReceiveRateCount;
            }
            else if (Name == "hysteria-padding")
            {
                ++PaddingCount;
            }
        }
        if (UdpCount > 1 || ReceiveRateCount > 1 || PaddingCount > 1)
        {
            return std::unexpected(AuthError::InvalidResponse);
        }
        if (!Udp.empty() && Udp != "true" && Udp != "false")
        {
            return std::unexpected(AuthError::InvalidResponse);
        }
        Result.UdpEnabled = Udp == "true";
        if (ReceiveRate == "auto")
        {
            Result.ReceiveRate = AutomaticReceiveRate{};
        }
        else if (!ReceiveRate.empty())
        {
            std::uint64_t NumericRate = 0;
            if (!ParseUnsigned(ReceiveRate, NumericRate))
            {
                return std::unexpected(AuthError::InvalidResponse);
            }
            Result.ReceiveRate = NumericRate;
        }
        return Result;
    }

    inline auto BuildAuthFailureResponse(
        const std::int64_t StreamId,
        const AuthError Error) -> Preview::Http3::ResponseHead
    {
        std::uint16_t Status = 0;
        switch (Error)
        {
        case AuthError::Unauthorized:
            Status = 401;
            break;
        case AuthError::InvalidRequest:
            Status = 400;
            break;
        case AuthError::AlreadyAuthenticated:
            Status = 409;
            break;
        case AuthError::AuthenticatorUnavailable:
            Status = 503;
            break;
        case AuthError::StreamQuota:
            Status = 429;
            break;
        case AuthError::Closed:
            Status = 500;
            break;
        }
        auto Owner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::HeaderBlock Headers(Owner);
        AddHeader(Headers, "content-length", "0");
        return Preview::Http3::ResponseHead{
            StreamId, Status, std::move(Headers), true};
    }

    inline auto Http3AuthSession::HandleRequest(Preview::Http3::RequestEvent Request)
        -> std::expected<Preview::Http3::ResponseHead, AuthError>
    {
        BindOwnerThread();
        if (Closed_)
        {
            return std::unexpected(AuthError::Closed);
        }
        if (Authenticated())
        {
            return std::unexpected(AuthError::AlreadyAuthenticated);
        }
        if (Request.StreamId < 0)
        {
            return std::unexpected(AuthError::InvalidRequest);
        }
        std::string_view Method;
        std::string_view Path;
        std::string_view Scheme;
        std::string_view Credential;
        std::size_t MethodCount = 0;
        std::size_t PathCount = 0;
        std::size_t SchemeCount = 0;
        std::size_t CredentialCount = 0;
        std::size_t AuthorityCount = 0;
        bool RegularFieldSeen = false;
        for (const auto &Field : Request.Head.Headers.Fields)
        {
            const std::string_view Name{Field.Name.data(), Field.Name.size()};
            const std::string_view Value{Field.value.data(), Field.value.size()};
            if (Name.empty())
            {
                return std::unexpected(AuthError::InvalidRequest);
            }
            if (Name.front() == ':')
            {
                if (RegularFieldSeen)
                {
                    return std::unexpected(AuthError::InvalidRequest);
                }
                if (Name != ":method" && Name != ":path" &&
                    Name != ":authority" && Name != ":scheme")
                {
                    return std::unexpected(AuthError::InvalidRequest);
                }
            }
            else
            {
                RegularFieldSeen = true;
            }
            if (Name == ":method")
            {
                ++MethodCount;
                Method = Value;
            }
            else if (Name == ":path")
            {
                ++PathCount;
                Path = Value;
            }
            else if (Name == ":authority")
            {
                ++AuthorityCount;
            }
            else if (Name == ":scheme")
            {
                ++SchemeCount;
                Scheme = Value;
            }
            else if (Name == "hysteria-auth")
            {
                ++CredentialCount;
                Credential = Value;
            }
        }
        if (MethodCount != 1 || PathCount != 1 ||
            SchemeCount != 1 || AuthorityCount != 1 || CredentialCount != 1 ||
            Method != "POST" || Path != "/auth" || Scheme != "https" ||
            Credential.empty())
        {
            return std::unexpected(AuthError::InvalidRequest);
        }
        if (!Options_.Authenticator)
        {
            return std::unexpected(AuthError::AuthenticatorUnavailable);
        }
        auto Result = Options_.Authenticator->Authenticate(Preview::AuthenticationRequest{
            .AccountId = {},
            .Identity = {},
            .Credential = Preview::Account::CredentialView::Token(Credential),
            .Rate = {}});
        if (!Result || !*Result)
        {
            return std::unexpected(AuthError::Unauthorized);
        }
        Result_ = std::move(Result);

        auto Owner = std::make_shared<Preview::Memory::SessionResource<>>();
        Preview::Http3::HeaderBlock Headers(Owner);
        AddHeader(Headers, "hysteria-udp", "true");
        AddHeader(Headers, "hysteria-cc-rx", "0");
        AddHeader(Headers, "hysteria-padding", "256");
        return Preview::Http3::ResponseHead{
            Request.StreamId, 233, std::move(Headers), false};
    }

    inline auto Http3AuthSession::AcquireStream()
        -> std::expected<Preview::Account::StreamLease, AuthError>
    {
        BindOwnerThread();
        if (Closed_)
        {
            return std::unexpected(AuthError::Closed);
        }
        if (!Authenticated())
        {
            return std::unexpected(AuthError::Unauthorized);
        }
        if (!Result_)
        {
            return std::unexpected(AuthError::Unauthorized);
        }
        auto Lease = Result_->TryAcquireStream();
        if (!Lease)
        {
            return std::unexpected(AuthError::StreamQuota);
        }
        return std::move(*Lease);
    }

    inline auto Http3AuthSession::Close() noexcept -> void
    {
        BindOwnerThread();
        if (Closed_)
        {
            return;
        }
        Closed_ = true;
        Result_ = Preview::AuthenticationResult{};
    }

} // namespace Preview::Hysteria2
