/**
 * @file ForwardResponseTransport.cpp
 * @brief HTTP/1.1 源站响应定界传输实现。
 */

#include <Prism/Protocols/Http1/ForwardResponseTransport.hpp>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Protocols/Common/IoBridge.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

namespace Prism::Http11
{
    namespace
    {
        [[nodiscard]] auto ProtocolFailure(const Prism::Error ErrorValue)
            -> Prism::Fault::Failure
        {
            return Prism::Fault::FromNative(Prism::make_error_code(ErrorValue));
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
                Prism::Protocols::StartPartialRead(
                    Prism::Protocols::PartialReadInput<ForwardResponseTransport>{
                        Owner(), Buffer, Executor()},
                    std::move(Handler));
            }

            /** @brief 部分写入；保留底层短写语义。 */
            auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
            {
                Prism::Protocols::StartPartialWrite(
                    Prism::Protocols::PartialWriteInput<ForwardResponseTransport>{
                        Owner(), Buffer, Executor()},
                    std::move(Handler));
            }

            /** @brief 真实写半关闭转交底层载体；反向读取仍然可用。 */
            auto StartWriteShutdown(Completion Handler) -> void override
            {
                if (!Inner_)
                {
                    Prism::Transmission::PostResult(
                        Executor(),
                        std::move(Handler),
                        Prism::IoResult{0, ProtocolFailure(Prism::Error::NotOpen)});
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
                    Failure_ = Prism::Fault::FromNative(
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
                -> boost::asio::awaitable<Prism::IoResult>
            {
                if (Buffer.empty())
                {
                    co_return Prism::IoResult{0, {}};
                }
                if (Failure_.Failed())
                {
                    co_return Prism::IoResult{0, Failure_};
                }
                if (Complete_)
                {
                    co_return Prism::IoResult{
                        0, Prism::Fault::Failure{Prism::Fault::Code::Eof}};
                }
                if (Closed_ || !Inner_)
                {
                    co_return Prism::IoResult{0, ProtocolFailure(Prism::Error::NotOpen)};
                }

                const auto Part = co_await Inner_->ReadSome(Buffer);
                const auto Count = Part.Bytes;
                if (Count > Buffer.size())
                {
                    SetFailure(ProtocolFailure(Prism::Error::BadLength));
                    co_return Prism::IoResult{0, Failure_};
                }
                if (Failure_.Failed())
                {
                    co_return Prism::IoResult{Count, Failure_};
                }

                const auto Result = Framing_.Consume(Buffer.first(Count));
                if (Result.Accepted > Count)
                {
                    SetFailure(ProtocolFailure(Prism::Error::BadLength));
                    co_return Prism::IoResult{0, Failure_};
                }
                if (Result.ErrorCode != Prism::Error::None)
                {
                    SetFailure(ProtocolFailure(Result.ErrorCode));
                    co_return Prism::IoResult{Result.Accepted, Failure_};
                }

                if (Part.Failure.Failed())
                {
                    if (Part.Failure.Code != Prism::Fault::Code::Eof)
                    {
                        SetFailure(Part.Failure);
                        co_return Prism::IoResult{Result.Accepted, Failure_};
                    }
                    const auto EndError = Framing_.EndOfInput();
                    if (EndError != Prism::Error::None)
                    {
                        SetFailure(ProtocolFailure(EndError));
                        co_return Prism::IoResult{Result.Accepted, Failure_};
                    }
                    Complete_ = true;
                    co_return Prism::IoResult{Result.Accepted, Part.Failure};
                }
                else if (Count == 0U)
                {
                    const auto EndError = Framing_.EndOfInput();
                    if (EndError != Prism::Error::None)
                    {
                        SetFailure(ProtocolFailure(EndError));
                        co_return Prism::IoResult{0, Failure_};
                    }
                    Complete_ = true;
                    co_return Prism::IoResult{
                        0, Prism::Fault::Failure{Prism::Fault::Code::Eof}};
                }

                if (Result.Complete)
                {
                    Complete_ = true;
                }
                co_return Prism::IoResult{Result.Accepted, {}};
            }

            /** @brief 数据面部分写入实现，由正式前门复用。 */
            [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer)
                -> boost::asio::awaitable<Prism::IoResult>
            {
                if (Closed_ || !Inner_)
                {
                    co_return Prism::IoResult{0, ProtocolFailure(Prism::Error::NotOpen)};
                }
                const auto Part = co_await Inner_->WriteSome(Buffer);
                if (Part.Bytes > Buffer.size())
                {
                    co_return Prism::IoResult{0, ProtocolFailure(Prism::Error::BadLength)};
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

            auto SetFailure(Prism::Fault::Failure Failure) -> void
            {
                if (Failure.Succeeded())
                {
                    Failure = ProtocolFailure(Prism::Error::IoError);
                }
                Failure_ = std::move(Failure);
            }

            SharedTransmission Inner_;
            ForwardResponseFraming Framing_;
            Prism::Fault::Failure Failure_;
            bool Closed_{false};
            bool Complete_{false};
        };
    } // namespace

    auto MakeForwardResponseTransport(ForwardResponseTransportOptions Options)
        -> SharedTransmission
    {
        if (!Options.Inner)
        {
            return {};
        }
        return std::make_shared<ForwardResponseTransport>(std::move(Options));
    }
} // namespace Prism::Http11
