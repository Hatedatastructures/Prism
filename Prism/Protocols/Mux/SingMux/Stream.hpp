/** @file Stream.hpp @brief sing-mux typed target 与首次响应的可靠 child owner。 */
#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <array>
#include <chrono>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
namespace Prism::Mux::SingMux
{
    class ServerStream final : public Prism::Transmission
    {
    public:
        ServerStream(Prism::SharedTransmission Next, Prism::Network::Target TargetValue)
            : Prism::Transmission(Next ? Next->Executor() : Net::any_io_executor{}),
              Next_(std::move(Next)), Target_(std::move(TargetValue))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Next_ ? Next_->Executor() : Net::any_io_executor{};
        }

        /** @brief 透传部分读；底层缺失时异步交付一次 not_connected。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            if (!Next_)
            {
                Prism::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler), Prism::IoResult{0, Missing()});
                return;
            }
            Next_->ReadSome(Buffer, std::move(Handler));
        }

        /** @brief 首次写入先交付 typed 目标响应再写应用数据；结果经正式前门恰好交付一次。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(StreamWrite{std::static_pointer_cast<ServerStream>(
                                     Transmission::shared_from_this()),
                                 Buffer},
                     std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层载体；反向读取仍然可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!Next_)
            {
                Prism::Transport::Detail::PostResult(
                    Executor(),
                    std::move(Handler), Prism::IoResult{0, Missing()});
                return;
            }
            Next_->WriteShutdown(std::move(Handler));
        }

        /** @brief 关闭底层载体并交付命令；实际退出由 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (!Next_)
            {
                return {};
            }
            return Next_->Close();
        }

        /** @brief 取消底层挂起操作；不改变已经确立的首次响应事实。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (!Next_)
            {
                return {};
            }
            return Next_->Cancel();
        }

        auto SetTimeout(const std::chrono::milliseconds Timeout) -> void override
        {
            if (Next_)
            {
                Next_->SetTimeout(Timeout);
            }
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Next_ && Next_->IsOpen();
        }

        [[nodiscard]] auto Target() const noexcept -> const Prism::Network::Target &
        {
            return Target_;
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return Next_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission * override
        {
            return Next_.get();
        }

    private:
        /** @brief 底层缺失时的原生错误身份；不创建第二套错误事实。 */
        [[nodiscard]] static auto Missing() -> Prism::Fault::Failure
        {
            return Prism::Fault::FromNative(std::make_error_code(std::errc::not_connected));
        }
        /** @brief 原协程体：首次响应与应用数据写入，保留完整写入与错误映射。 */
        [[nodiscard]] auto WritePartial(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
        {
            if (!Next_)
            {
                ErrorCode = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (!ResponseWritten_)
            {
                const std::array<std::byte, 1> Status{std::byte{0x00}};
                if (!co_await WriteAll(Status, ErrorCode))
                {
                    co_return 0;
                }
                ResponseWritten_ = true;
            }
            if (Buffer.empty())
            {
                ErrorCode.clear();
                co_return 0;
            }
            if (!co_await WriteAll(Buffer, ErrorCode))
            {
                co_return 0;
            }
            ErrorCode.clear();
            co_return Buffer.size();
        }
        struct StreamWrite final
        {
            std::shared_ptr<ServerStream> Owner;
            std::span<const std::byte> Buffer;
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, StreamWrite Input) const -> void
            {
                Prism::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code ErrorCode;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer, ErrorCode), Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(ErrorCode)}};
            }
        };
        /** @brief 在 owner executor 上启动一次部分写；结果经正式前门恰好交付一次。 */
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }
        /** @brief 底层完整写入循环；IoResult 的字节与失败同次映射回本地 error_code。 */
        [[nodiscard]] auto WriteAll(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<bool>
        {
            std::size_t Offset = 0;
            while (Offset < Buffer.size())
            {
                const auto Remaining = Buffer.size() - Offset;
                const auto Part = co_await Next_->WriteSome(Buffer.subspan(Offset));
                ErrorCode = Prism::Fault::ToNative(Part.Failure);
                if (ErrorCode || Part.Bytes == 0 || Part.Bytes > Remaining)
                {
                    if (!ErrorCode)
                    {
                        ErrorCode = std::make_error_code(std::errc::broken_pipe);
                    }
                    co_return false;
                }
                Offset += Part.Bytes;
            }
            co_return true;
        }

        Prism::SharedTransmission Next_;
        Prism::Network::Target Target_;
        bool ResponseWritten_{false};
    };

}
