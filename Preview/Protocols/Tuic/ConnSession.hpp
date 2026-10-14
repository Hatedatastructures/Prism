/**
 * @file ConnSession.hpp
 * @brief TUIC 连接级资源与状态 owner。
 * @details 持有底层传输、会话内存、认证器所有权、账户租约以及跨认证、
 *          stream 和 datagram 阶段共享的协议状态。具体行为由 ConnIo、
 *          ConnAuth、ConnStream 和 ConnDatagram 借用本对象完成。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Account/Lease.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Tuic/Types.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Tuic::detail
{

    namespace Net = boost::asio;

    /**
     * @class ConnSession
     * @brief TUIC 连接级共享状态和资源 owner。
     * @tparam Memory 会话内存策略
     * @note 实例非线程安全；所有状态转换由上层连接 executor 串行执行。
     */
    template <Preview::Memory::Restrict Memory>
    class ConnSession final
    {
    public:
        explicit ConnSession(
            SharedTransmission Upstream,
            std::array<std::uint8_t, UuidLen> Uuid,
            Preview::SharedAuthenticator AuthenticatorOwner = {})
            : NextLayer_(std::move(Upstream)),
              Uuid_(Uuid),
              AuthOwner_(std::move(AuthenticatorOwner))
        {
        }

        ConnSession(const ConnSession &) = delete;
        auto operator=(const ConnSession &) -> ConnSession & = delete;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return NextLayer_ ? NextLayer_->Executor() : Net::any_io_executor{};
        }

        [[nodiscard]] auto Underlying() const noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission *
        {
            return NextLayer_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission *
        {
            return NextLayer_.get();
        }

        /**
         * @brief 关闭连接并释放连接级认证租约。
         * @details 关闭顺序保持为先清理协议状态，再通知底层传输。
         */
        /** @brief 先清协议状态，再封止并交付底层关闭；实际退出由 Activity()->Drain() 等待。 */
        [[nodiscard]] auto Close() -> Preview::Transmission::ControlResult
        {
            ResetConnectionState();
            if (NextLayer_)
            {
                return NextLayer_->Close();
            }
            return {};
        }

        /** @brief 取消底层挂起操作，但保留认证状态供调用方决定后续处理。 */
        [[nodiscard]] auto Cancel() -> Preview::Transmission::ControlResult
        {
            if (NextLayer_)
            {
                return NextLayer_->Cancel();
            }
            return {};
        }

        /**
         * @brief 释放底层传输所有权。
         * @details 与旧 Conn::Release() 一致，释放连接级账户租约和握手状态。
         */
        [[nodiscard]] auto Release() -> SharedTransmission
        {
            ResetConnectionState();
            return std::move(NextLayer_);
        }

        [[nodiscard]] auto Arena() noexcept -> Preview::Memory::ResourcePointer
        {
            return Mem_.Arena();
        }

        [[nodiscard]] auto Uuid() const noexcept
            -> const std::array<std::uint8_t, UuidLen> &
        {
            return Uuid_;
        }

        [[nodiscard]] auto Authenticator() const noexcept -> const Preview::Authenticator *
        {
            return AuthOwner_.get();
        }

        [[nodiscard]] auto IsAuthenticated() const noexcept -> bool
        {
            return Authenticated_;
        }

        auto SetAuthenticated(const bool Value) noexcept -> void
        {
            Authenticated_ = Value;
        }

        [[nodiscard]] auto IsHandshaken() const noexcept -> bool
        {
            return Handshaken_;
        }

        auto SetHandshaken(const bool Value) noexcept -> void
        {
            Handshaken_ = Value;
        }

        /** @brief 开始服务端认证，清除上一次认证产生的连接租约和身份。 */
        auto BeginAuthentication() noexcept -> void
        {
            Authenticated_ = false;
            Handshaken_ = false;
            AuthLease_.Release();
            AccountId_ = {};
            Identity_.clear();
        }

        /** @brief 客户端重新发送认证帧时只重置阶段标志，保持原有租约语义。 */
        auto BeginClientAuthentication() noexcept -> void
        {
            Authenticated_ = false;
            Handshaken_ = false;
        }

        [[nodiscard]] auto TakeAuthLease() -> Preview::Account::AccountLease
        {
            return std::move(AuthLease_);
        }

        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId
        {
            return AccountId_;
        }

        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Identity_;
        }

        auto SetAuthenticationResult(
            Preview::AccountId AccountId,
            Preview::Account::AccountLease Lease,
            std::string Identity) -> void
        {
            Authenticated_ = true;
            AccountId_ = AccountId;
            AuthLease_ = std::move(Lease);
            Identity_ = std::move(Identity);
        }

        [[nodiscard]] auto Parsed() const noexcept -> const Message &
        {
            return Parsed_;
        }

        auto SetParsed(Message Value) -> void
        {
            Parsed_ = std::move(Value);
        }

        auto SetTarget(const Address &Value) -> void
        {
            Target_ = Value;
        }

        [[nodiscard]] auto AssocId() const noexcept -> std::uint32_t
        {
            return AssocId_;
        }

        [[nodiscard]] auto PacketId() const noexcept -> std::uint16_t
        {
            return PacketId_;
        }

        auto AdvancePacketId() noexcept -> void
        {
            ++PacketId_;
        }

    private:
        auto ResetConnectionState() noexcept -> void
        {
            Handshaken_ = false;
            Authenticated_ = false;
            AuthLease_.Release();
            AccountId_ = {};
            Identity_.clear();
        }

        SharedTransmission NextLayer_{};
        std::array<std::uint8_t, UuidLen> Uuid_{};
        Preview::SharedAuthenticator AuthOwner_{};
        Preview::Account::AccountLease AuthLease_{};
        Preview::AccountId AccountId_{};
        std::string Identity_{};
        Address Target_{};
        Message Parsed_{};
        std::uint32_t AssocId_{0};
        std::uint16_t PacketId_{0};
        bool Handshaken_{false};
        bool Authenticated_{false};
        Memory Mem_{};
    };

} // namespace Preview::Tuic::detail
