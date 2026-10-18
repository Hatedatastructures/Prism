/**
 * @file ConnSession.hpp
 * @brief VMess 连接会话状态与资源 owner。
 * @details 只持有底层传输、协议凭据、认证租约、会话内存和跨阶段状态。
 *          握手、chunk 数据面和精确 I/O 分别由专用 owner 借用这些资源。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <Prism/Account/Authenticator.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Vmess/RequestCodec.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Vmess::detail
{

    namespace Net = boost::asio;

    /**
     * @brief VMess Conn 的会话级所有权和状态。
     * @tparam Memory 会话内存策略
     * @details 上游传输和认证租约都由本对象持有；其他 owner 只通过
     *          Conn 聚合入口访问同一个生命周期边界。
     */
    template <Prism::Memory::Restrict Memory>
    struct ConnSession final
    {
        explicit ConnSession(
            std::array<std::uint8_t, 16> Uuid,
            RandomSource Source,
            Prism::SharedAuthenticator AuthOwner)
            : Uuid_(Uuid),
              Random_(std::move(Source)),
              AuthOwner_(std::move(AuthOwner))
        {
        }

        [[nodiscard]] auto Authenticator() const noexcept -> const Prism::Authenticator *
        {
            return AuthOwner_.get();
        }

        ConnSession(const ConnSession &) = delete;
        auto operator=(const ConnSession &) -> ConnSession & = delete;

        /** @brief 绑定新的底层传输并清除上一轮握手状态。 */
        auto Reset(Prism::SharedTransmission Upstream, bool ServerSide) -> void
        {
            NextLayer_ = std::move(Upstream);
            Handshaken_ = false;
            ServerSide_ = ServerSide;
            AuthId_.fill(0);
            AuthLease_.Release();
            AccountId_ = {};
            Identity_.clear();
            Parsed_ = Message{};
        }

        /** @brief 封止并交付底层关闭；实际退出由 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto Close() noexcept -> Prism::Transmission::ControlResult
        {
            if (NextLayer_)
            {
                return NextLayer_->Close();
            }
            return {};
        }

        /** @brief 可重复取消底层 I/O；成功不表示连接已关闭。 */
        [[nodiscard]] auto Cancel() noexcept -> Prism::Transmission::ControlResult
        {
            if (NextLayer_)
            {
                return NextLayer_->Cancel();
            }
            return {};
        }

        [[nodiscard]] auto Release() noexcept -> Prism::SharedTransmission
        {
            return std::move(NextLayer_);
        }

        [[nodiscard]] auto IsHandshaken() const noexcept -> bool
        {
            return Handshaken_;
        }

        [[nodiscard]] auto Arena() noexcept -> Prism::Memory::ResourcePointer
        {
            return Mem_.Arena();
        }

        Prism::SharedTransmission NextLayer_{};
        std::array<std::uint8_t, 16> AuthId_{};
        Message Parsed_{};
        std::array<std::uint8_t, 16> Uuid_{};
        RandomSource Random_{};
        Prism::SharedAuthenticator AuthOwner_{};
        Prism::Account::AccountLease AuthLease_{};
        Prism::AccountId AccountId_{};
        std::string Identity_{};
        Memory Mem_{};
        bool Handshaken_{false};
        bool ServerSide_{false};
    };

} // namespace Prism::Vmess::detail
