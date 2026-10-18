/**
 * @file ForwardRequestTransport.hpp
 * @brief HTTP/1.1 首请求状态 owner 到 Transmission 的唯一边界。
 * @details 本类只接入正式 typed I/O 前门；framing、Upgrade 与半关闭状态由
 *          ForwardRequestState 独占拥有，借用缓冲区只活到对应 completion 返回。
 */
#pragma once

#include <memory>
#include <span>
#include <utility>

#include <boost/asio/awaitable.hpp>

#include <Prism/Protocols/Common/IoBridge.hpp>
#include <Prism/Protocols/Http1/ForwardRequest.hpp>
#include <Prism/Protocols/Http1/ForwardRequestState.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Http11
{
    namespace
    {
        class ForwardRequestTransport final : public Prism::Transmission
        {
        public:
            explicit ForwardRequestTransport(ForwardRequestOptions Options)
                : Prism::Transmission(Options.Inner->Executor()), State_(std::move(Options))
            {
            }

            [[nodiscard]] auto Executor() const -> ExecutorType override
            {
                return State_.Executor();
            }

            [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
            {
                return State_.NextLayer();
            }

            [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission * override
            {
                return State_.NextLayer();
            }

            /** @brief 通过 owner executor 恰好交付一次 typed 部分读结果。 */
            auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
            {
                Prism::Protocols::StartPartialRead(
                    Prism::Protocols::PartialReadInput<ForwardRequestTransport>{
                        Owner(), Buffer, Executor()},
                    std::move(Handler));
            }

            /** @brief 通过 owner executor 恰好交付一次 typed 部分写结果。 */
            auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
            {
                Prism::Protocols::StartPartialWrite(
                    Prism::Protocols::PartialWriteInput<ForwardRequestTransport>{
                        Owner(), Buffer, Executor()},
                    std::move(Handler));
            }

            /** @brief 委托首请求状态 owner 执行写半关闭。 */
            auto StartWriteShutdown(Completion Handler) -> void override
            {
                State_.StartWriteShutdown(std::move(Handler));
            }

            /** @brief 关闭请求 framing owner 与唯一内层传输。 */
            [[nodiscard]] auto OnClose() -> ControlResult override
            {
                return State_.Close();
            }

            /** @brief 记录取消并取消同一 owner 下的挂起操作。 */
            [[nodiscard]] auto OnCancel() -> ControlResult override
            {
                return State_.Cancel();
            }

            [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
                -> boost::asio::awaitable<Prism::IoResult>
            {
                return State_.ReadPartial(Buffer);
            }

            [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
                -> boost::asio::awaitable<Prism::IoResult>
            {
                return State_.WritePartial(Buffer);
            }

            [[nodiscard]] auto IsOpen() const -> bool override
            {
                return State_.IsOpen();
            }

        private:
            [[nodiscard]] auto Owner() -> std::shared_ptr<ForwardRequestTransport>
            {
                return std::static_pointer_cast<ForwardRequestTransport>(
                    Prism::Transmission::shared_from_this());
            }

            Detail::ForwardRequestState State_;
        };
    } // namespace

    inline auto MakeForwardRequestTransport(ForwardRequestOptions Options) -> SharedTransmission
    {
        if (!Options.Inner)
        {
            return {};
        }
        return std::make_shared<ForwardRequestTransport>(std::move(Options));
    }
} // namespace Prism::Http11
