/**
 * @file ConnSession.hpp
 * @brief Shadowsocks 2022 连接会话状态与资源所有者。
 * @details 只持有底层传输、PSK、认证租约、会话内存和跨阶段状态。
 *          握手、record 编解码和 UDP 数据面分别由专用 owner 访问这些状态。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022::detail
{

    namespace Net = boost::asio;

    /**
     * @brief SS2022 Conn 的会话级资源和协议状态。
     * @tparam Memory 会话内存策略
     * @details 底层传输和账户租约均由该对象持有，拆分出的行为 owner
     *          只借用本对象，不改变协议边界或 Composition 所有权。
     */
    template <Preview::Memory::Restrict Memory>
    struct ConnSession final
    {
        using Buffer = typename Memory::template Buffer<std::uint8_t>;

        explicit ConnSession(
            std::array<std::uint8_t, 16> PskValue,
            std::uint64_t TimeWindowValue,
            Preview::SharedAuthenticator AuthenticatorOwner)
            : Psk_(PskValue),
              TimeWindow_(TimeWindowValue),
              AuthOwner_(std::move(AuthenticatorOwner)),
              PlainRx_(Mem_.Arena()),
              UdpRx_(Mem_.Arena()),
              UdpBuf_(Mem_.Arena())
        {
        }

        ConnSession(const ConnSession &) = delete;
        auto operator=(const ConnSession &) -> ConnSession & = delete;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return NextLayer_ ? NextLayer_->Executor() : Net::any_io_executor{};
        }

        auto SetUpstream(Preview::SharedTransmission Upstream) -> void
        {
            NextLayer_ = std::move(Upstream);
        }

        /** @brief 封止并交付底层关闭；实际退出由底层 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto Close() -> Preview::Transmission::ControlResult
        {
            if (NextLayer_)
            {
                return NextLayer_->Close();
            }
            return {};
        }

        /** @brief 可重复取消底层挂起操作；成功只表示命令已接管。 */
        [[nodiscard]] auto Cancel() -> Preview::Transmission::ControlResult
        {
            if (NextLayer_)
            {
                return NextLayer_->Cancel();
            }
            return {};
        }

        Preview::SharedTransmission NextLayer_{};
        std::array<std::uint8_t, 16> Psk_{};
        std::uint64_t TimeWindow_{90};
        Preview::SharedAuthenticator AuthOwner_{};

        Preview::Account::AccountLease AuthLease_{};
        Preview::AccountId AccountId_{};
        std::string Identity_{};
        std::array<std::uint8_t, 16> SessionKey_{};
        std::array<std::uint8_t, 16> ClientSalt_{};
        Message Parsed_{};
        Memory Mem_{};
        Buffer PlainRx_;
        std::size_t PlainOff_{0};
        Buffer UdpRx_;
        std::uint64_t UdpPktId_{0};
        Buffer UdpBuf_;
        std::size_t UdpUsed_{0};
        bool Handshaken_{false};
        bool Eof_{false};
    };

} // namespace Preview::Shadowsocks2022::detail
