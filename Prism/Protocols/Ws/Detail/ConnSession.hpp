/**
 * @file ConnSession.hpp
 * @brief WebSocket 连接级状态与底层传输所有权。
 * @details ConnSession 持有跨握手、帧和关闭 owner 共享的连接状态、底层 Transmission
 *          与 BytePool。资源保留至活动排空后销毁，不绑定 executor，不负责取消或关闭。
 * @note 实例非线程安全，应在同一协程或线程内使用。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>

#include <memory>
#include <string>
#include <utility>

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Ws/Detail/FrameWriteGate.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Ws::Detail
{

    namespace Net = boost::asio;

    /**
     * @class ConnSession
     * @brief WebSocket 连接状态与底层传输所有者。
     * @tparam Memory 会话内存策略。
     */
    template <Prism::Memory::Restrict Memory>
    class ConnSession final
    {
    public:
        /**
         * @param Upstream 底层传输共享 owner；executor 由此继承。
         * @param Bytes 同一连接生命周期的有界字节池共享 owner。
         * @param Client 客户端视角；客户端发送帧需要掩码。
         */
        explicit ConnSession(
            SharedTransmission Upstream,
            std::shared_ptr<Prism::Memory::BytePool> Bytes,
            bool Client)
            : NextLayer_(std::move(Upstream)),
              Bytes_(std::move(Bytes)),
              Client_(Client)
        {
            if (NextLayer_)
            {
                FrameWriter_ = std::make_shared<FrameWriteGate>(NextLayer_->Executor());
            }
        }

        ConnSession(const ConnSession &) = delete;
        auto operator=(const ConnSession &) -> ConnSession & = delete;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            if (!NextLayer_)
            {
                return {};
            }
            return NextLayer_->Executor();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission *
        {
            return NextLayer_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept
            -> const Prism::Transmission *
        {
            return NextLayer_.get();
        }

        [[nodiscard]] auto Underlying() const -> SharedTransmission
        {
            return NextLayer_;
        }

        [[nodiscard]] auto Release() -> SharedTransmission
        {
            MarkClosed(true);
            return std::move(NextLayer_);
        }

        [[nodiscard]] auto HasUpstream() const noexcept -> bool
        {
            return NextLayer_ != nullptr;
        }

        [[nodiscard]] auto HasBytes() const noexcept -> bool
        {
            return Bytes_ != nullptr;
        }

        [[nodiscard]] auto Bytes() const noexcept
            -> const std::shared_ptr<Prism::Memory::BytePool> &
        {
            return Bytes_;
        }

        /** @brief 取得连接唯一帧写入权，持有至完整帧写完或操作退出。 */
        [[nodiscard]] auto AcquireFrameWriter()
            -> Net::awaitable<std::expected<FrameWritePermit, Prism::Fault::Failure>>
        {
            if (!FrameWriter_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            co_return co_await FrameWriter_->Acquire();
        }

        /** @brief 最终关闭时封止写入并唤醒所有排队帧写者。 */
        auto CloseFrameWriter() noexcept -> void
        {
            if (FrameWriter_)
            {
                FrameWriter_->Close();
            }
        }

        [[nodiscard]] auto IsClient() const noexcept -> bool
        {
            return Client_;
        }

        [[nodiscard]] auto IsHandshaken() const noexcept -> bool
        {
            return Handshaken_;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool
        {
            return Closed_;
        }

        [[nodiscard]] auto Accept() const noexcept -> const std::string &
        {
            return Accept_;
        }

        auto BeginHandshake() -> void
        {
            Handshaken_ = false;
            Closed_ = false;
            Accept_.clear();
        }

        auto MarkHandshaken(std::string Accept) -> void
        {
            Accept_ = std::move(Accept);
            Handshaken_ = true;
            Closed_ = false;
        }

        auto MarkClosed(bool ResetHandshake) noexcept -> void
        {
            Closed_ = true;
            if (ResetHandshake)
            {
                Handshaken_ = false;
            }
        }

    private:
        SharedTransmission NextLayer_;
        std::shared_ptr<Prism::Memory::BytePool> Bytes_;
        std::string Accept_;
        bool Client_{false};
        bool Handshaken_{false};
        bool Closed_{false};
        std::shared_ptr<FrameWriteGate> FrameWriter_;
    };

} // namespace Prism::Ws::Detail
