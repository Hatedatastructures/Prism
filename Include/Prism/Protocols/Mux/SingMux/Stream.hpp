/** @file Stream.hpp @brief sing-mux typed target 与首次响应的可靠 child owner。 */
#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <cstddef>
#include <tuple>
namespace Prism::Mux::SingMux
{
    class ServerStream final : public Prism::Transmission
    {
    public:
        /**
         * @brief 包装已解析的 child 传输，并可先交付一次请求读取终态。
         * @param Next 共享持有的 child 传输；ServerStream 负责其关闭与取消转发。
         * @param TargetValue 按值保存的已解析目标。
         * @param PendingReadTerminal 已由请求解析消费的终态，只在首次 ReadSome 中交付一次。
         */
        ServerStream(
            Prism::SharedTransmission Next,
            Prism::Network::Target TargetValue,
            std::optional<Prism::Fault::Failure> PendingReadTerminal)
            : Prism::Transmission(Next ? Next->Executor() : Net::any_io_executor{}),
              Next_(std::move(Next)), Target_(std::move(TargetValue)),
              PendingReadTerminal_(std::move(PendingReadTerminal))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Next_ ? Next_->Executor() : Net::any_io_executor{};
        }

        /** @brief 透传部分读；底层缺失时异步交付一次 not_connected。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override;

        /** @brief 首次写入先交付 typed 目标响应再写应用数据；结果经正式前门恰好交付一次。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override;

        /** @brief 真实写半关闭转交底层载体；反向读取仍然可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (!Next_)
            {
                Prism::Transmission::PostResult(
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
        /** @brief 依次写入首次响应与应用数据，并保留真实写入进度及同次终态。 */
        [[nodiscard]] auto WritePartial(
            std::span<const std::byte> Buffer) -> Net::awaitable<Prism::IoResult>;
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
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                const auto Result = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer), Net::deferred);
                co_return std::tuple{Result};
            }
        };
        /** @brief 在 owner executor 上启动一次部分写；结果经正式前门恰好交付一次。 */
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }
        /** @brief 底层完整写入循环；失败时返回此前与本次真实完成的累计字节。 */
        [[nodiscard]] auto WriteAll(
            std::span<const std::byte> Buffer) -> Net::awaitable<Prism::IoResult>;

        Prism::SharedTransmission Next_;
        Prism::Network::Target Target_;
        std::optional<Prism::Fault::Failure> PendingReadTerminal_;
        std::atomic<bool> PendingReadTerminalConsumed_{false};
        bool ResponseWritten_{false};
    };

}
