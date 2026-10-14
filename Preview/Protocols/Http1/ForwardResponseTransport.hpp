/**
 * @file ForwardResponseTransport.hpp
 * @brief HTTP/1.1 源站响应定界传输
 * @details 将响应 framing 放在 Relay 下行源的一侧。完整消息的最后字节
 *          正常返回，下一次读取返回 clean EOF；关闭、取消和半关委托内层。
 */

#pragma once

#include <memory>
#include <algorithm>
#include <chrono>
#include <span>
#include <system_error>
#include <utility>

#include <Preview/Foundation/Utility/Http/ForwardResponseFraming.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Fault/Handling.hpp>
#include <Preview/Protocols/Common/IoBridge.hpp>
#include <Preview/Transport/Detail/IoCompletion.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Http11
{

    /**
     * @struct ForwardResponseTransportOptions
     * @brief 构造响应定界传输所需的拥有数据
     */
    struct ForwardResponseTransportOptions final
    {
        SharedTransmission Inner;
        ForwardResponseFramingOptions Framing;
    };

    /**
     * @brief 构造源站响应定界传输
     * @param Options 内层源站连接与请求响应语义
     * @return 定界后的传输；Inner 为空时返回空指针
     */
    [[nodiscard]] auto MakeForwardResponseTransport(ForwardResponseTransportOptions Options)
        -> SharedTransmission;

    namespace
    {
        [[nodiscard]] auto ProtocolFailure(const Error ErrorValue)
            -> Preview::Fault::Failure
        {
            return Preview::Fault::FromNative(Preview::make_error_code(ErrorValue));
        }

        class ForwardResponseTransport final : public Transmission
        {
        public:
            explicit ForwardResponseTransport(ForwardResponseTransportOptions Options)
                : Transmission(Options.Inner->Executor()),
                  Inner_(std::move(Options.Inner)), Framing_(Options.Framing)
            {
            }

            [[nodiscard]] auto Executor() const -> ExecutorType override
            {
                return Inner_->Executor();
            }

            [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
            {
                return Inner_.get();
            }

            [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
            {
                return Inner_.get();
            }

            /** @brief 部分读取；结果与借用沿正式前门交付一次。 */
            auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
            {
                Preview::Protocols::StartPartialRead(
                    Preview::Protocols::PartialReadInput<ForwardResponseTransport>{Owner(), Buffer, Executor()},
                    std::move(Handler));
            }

            /** @brief 部分写入；保留底层短写语义。 */
            auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
            {
                Preview::Protocols::StartPartialWrite(
                    Preview::Protocols::PartialWriteInput<ForwardResponseTransport>{Owner(), Buffer, Executor()},
                    std::move(Handler));
            }

            /** @brief 真实写半关闭转交底层载体；反向读取仍然可用。 */
            auto StartWriteShutdown(Completion Handler) -> void override
            {
                if (!Inner_)
                {
                    Preview::Transport::Detail::PostResult(
                        Executor(),
                        std::move(Handler),
                        Preview::IoResult{0, ProtocolFailure(Error::NotOpen)});
                    return;
                }
                Inner_->WriteShutdown(std::move(Handler));
            }

            /** @brief 封止响应解析状态并交付底层关闭。 */
            [[nodiscard]] auto OnClose() -> ControlResult override
            {
                Closed_ = true;
                if (!Inner_)
                {
                    return {};
                }
                return Inner_->Close();
            }

            /** @brief 记录取消事实并取消底层挂起操作；不宣称已经关闭。 */
            [[nodiscard]] auto OnCancel() -> ControlResult override
            {
                if (Failure_.Succeeded())
                {
                    Failure_ = Preview::Fault::FromNative(
                        std::make_error_code(std::errc::operation_canceled));
                }
                if (!Inner_)
                {
                    return {};
                }
                return Inner_->Cancel();
            }

            /** @brief 数据面部分读取实现，由正式前门复用。 */
            [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer)
                -> Net::awaitable<Preview::IoResult>
            {
                if (Buffer.empty())
                {
                    co_return Preview::IoResult{0, {}};
                }
                if (Failure_.Failed())
                {
                    co_return Preview::IoResult{0, Failure_};
                }
                if (Complete_)
                {
                    co_return Preview::IoResult{
                        0, Preview::Fault::Failure{Preview::Fault::Code::Eof}};
                }
                if (Closed_ || !Inner_)
                {
                    co_return Preview::IoResult{0, ProtocolFailure(Error::NotOpen)};
                }

                const auto Part = co_await Inner_->ReadSome(Buffer);
                const auto Count = Part.Bytes;
                if (Count > Buffer.size())
                {
                    SetFailure(ProtocolFailure(Error::BadLength));
                    co_return Preview::IoResult{0, Failure_};
                }
                if (Failure_.Failed())
                {
                    co_return Preview::IoResult{Count, Failure_};
                }

                const auto Result = Framing_.Consume(Buffer.first(Count));
                if (Result.Accepted > Count)
                {
                    SetFailure(ProtocolFailure(Error::BadLength));
                    co_return Preview::IoResult{0, Failure_};
                }
                if (Result.ErrorCode != Error::None)
                {
                    SetFailure(ProtocolFailure(Result.ErrorCode));
                    co_return Preview::IoResult{Result.Accepted, Failure_};
                }

                if (Part.Failure.Failed())
                {
                    if (Part.Failure.Code != Preview::Fault::Code::Eof)
                    {
                        SetFailure(Part.Failure);
                        co_return Preview::IoResult{Result.Accepted, Failure_};
                    }
                    const auto EndError = Framing_.EndOfInput();
                    if (EndError != Error::None)
                    {
                        SetFailure(ProtocolFailure(EndError));
                        co_return Preview::IoResult{Result.Accepted, Failure_};
                    }
                    Complete_ = true;
                    co_return Preview::IoResult{Result.Accepted, Part.Failure};
                }
                else if (Count == 0U)
                {
                    const auto EndError = Framing_.EndOfInput();
                    if (EndError != Error::None)
                    {
                        SetFailure(ProtocolFailure(EndError));
                        co_return Preview::IoResult{0, Failure_};
                    }
                    Complete_ = true;
                    co_return Preview::IoResult{
                        0, Preview::Fault::Failure{Preview::Fault::Code::Eof}};
                }

                if (Result.Complete)
                {
                    Complete_ = true;
                }
                co_return Preview::IoResult{Result.Accepted, {}};
            }

            /** @brief 数据面部分写入实现，由正式前门复用。 */
            [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
                -> Net::awaitable<Preview::IoResult>
            {
                if (Closed_ || !Inner_)
                {
                    co_return Preview::IoResult{0, ProtocolFailure(Error::NotOpen)};
                }
                const auto Part = co_await Inner_->WriteSome(Buffer);
                if (Part.Bytes > Buffer.size())
                {
                    co_return Preview::IoResult{0, ProtocolFailure(Error::BadLength)};
                }
                co_return Part;
            }

            auto SetTimeout(std::chrono::milliseconds Timeout) -> void override
            {
                if (Inner_)
                {
                    Inner_->SetTimeout(Timeout);
                }
            }

            [[nodiscard]] auto IsOpen() const -> bool override
            {
                return !Closed_ && Inner_ && Inner_->IsOpen();
            }

        private:
            /** @brief 完成交付前的 owner 借用；存活由本次传输预约与调用者共同保证。 */
            [[nodiscard]] auto Owner() -> std::shared_ptr<ForwardResponseTransport>
            {
                return std::static_pointer_cast<ForwardResponseTransport>(
                    Transmission::shared_from_this());
            }

            auto SetFailure(Preview::Fault::Failure Failure) -> void
            {
                if (Failure.Succeeded())
                {
                    Failure = ProtocolFailure(Error::IoError);
                }
                Failure_ = std::move(Failure);
            }

            SharedTransmission Inner_;
            ForwardResponseFraming Framing_;
            Preview::Fault::Failure Failure_;
            bool Closed_{false};
            bool Complete_{false};
        };
    } // namespace

    inline auto MakeForwardResponseTransport(ForwardResponseTransportOptions Options)
        -> SharedTransmission
    {
        if (!Options.Inner)
        {
            return {};
        }
        return std::make_shared<ForwardResponseTransport>(std::move(Options));
    }

} // namespace Preview::Http11
