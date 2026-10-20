/** @file Stream.hpp @brief AnyTLS 虚拟流的 owning 数据队列、整帧输出和 tracked FIN。 */
#pragma once
#include <Prism/Protocols/Anytls/Detail/Session/State.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <cstring>

namespace Prism::Anytls::Detail
{
    class StreamTransport final : public Prism::Transmission
    {
    public:
        struct Input final
        {
            std::shared_ptr<State> Root;
            std::shared_ptr<StreamState> Stream;
            std::vector<std::byte> Preread;
        };
        explicit StreamTransport(Input Value)
            : Prism::Transmission(Value.Root ? Value.Root->Executor : Net::any_io_executor{}),
              Root_(std::move(Value.Root)), Stream_(std::move(Value.Stream)), Pending_(std::move(Value.Preread)) {}
        auto Executor() const -> Net::any_io_executor override { return Root_->Executor; }
        /** @brief 部分读取；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ReadWork>(StreamRead{std::static_pointer_cast<StreamTransport>(Transmission::shared_from_this()), Buffer},
                     std::move(Handler));
        }
        /** @brief 部分写入；保留底层短写语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<WriteWork>(StreamWrite{std::static_pointer_cast<StreamTransport>(Transmission::shared_from_this()), Buffer},
                     std::move(Handler));
        }
        /** @brief 真实写半关闭：发送 tracked FIN；反向读取仍然可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            SendFin();
            Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {}});
        }
        /** @brief 关闭流：置位 Closed、唤醒接收方并发送 FIN。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (!Closed_)
            {
                Closed_ = true; Stream_->Data->close();
                SendFin();
            }
            return {};
        }
        /** @brief 取消挂起接收；不改变已经确立的 FIN 事实。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            Stream_->Data->close();
            return {};
        }
        auto IsOpen() const -> bool override { return !Closed_ && !Root_->Stopping.load(); }
    private:
        /** @brief 原协程体：部分读取，保留预读队列与 EOF 语义。 */
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code& Error)
            -> Net::awaitable<std::size_t>
        {
            if (Offset_ == Pending_.size())
            {
                Pending_.clear(); Offset_ = 0;
                if (Closed_) { Error = Prism::Fault::Code::Eof; co_return 0; }
                boost::system::error_code Received;
                Pending_ = co_await Stream_->Data->async_receive(Net::redirect_error(Net::use_awaitable, Received));
                if (Received) { Error = Prism::Fault::Code::Eof; co_return 0; }
            }
            const auto Count = (std::min)(Buffer.size(), Pending_.size() - Offset_);
            std::memcpy(Buffer.data(), Pending_.data() + Offset_, Count);
            Offset_ += Count; Error.clear();
            co_return Count;
        }
        /** @brief 原协程体：部分写入，保留短写与队列交付语义。 */
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer, std::error_code& Error)
            -> Net::awaitable<std::size_t>
        {
            if (Closed_ || Stream_->FinSent || Root_->Stopping.load())
            { Error = Prism::Fault::Code::IoError; co_return 0; }
            const auto Size = (std::min)(Buffer.size(), std::size_t{65535});
            const auto Result = co_await Root_->Writer->Send({Command::Push, Stream_->Id,
                std::vector<std::byte>(Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(Size))});
            if (Result.Failure.Failed())
            {
                Root_->RecordTerminalFailure(Result.Failure);
                Root_->Stop();
            }
            Error = Prism::Fault::ToNative(Result.Failure);
            co_return Result.PayloadBytes;
        }
        struct StreamRead final { std::shared_ptr<StreamTransport> Owner; std::span<std::byte> Buffer; };
        struct StreamWrite final { std::shared_ptr<StreamTransport> Owner; std::span<const std::byte> Buffer; };
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, StreamRead Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->ReadPartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, StreamWrite Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                std::error_code Error;
                const auto Count = co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->WritePartial(Input.Buffer, Error), Net::deferred);
                co_return std::tuple{Prism::IoResult{Count, Prism::Fault::FromNative(Error)}};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        static auto Finish(std::shared_ptr<State> Root, std::shared_ptr<StreamState> Stream) -> Net::awaitable<void>
        {
            if (Root->Stopping.load() || Stream->IsInputTerminated()) co_return;
            const auto Result = co_await Root->Writer->Send({Command::Fin, Stream->Id});
            if (Result.Failure.Failed())
            {
                Root->RecordTerminalFailure(Result.Failure);
                Root->Stop();
            }
        }
        auto SendFin() -> void
        {
            if (Stream_->FinSent || Stream_->IsInputTerminated() || Root_->Stopping.load()) return;
            Stream_->FinSent = true;
            Prism::Lifecycle::TaskRequest Request{.Context = Prism::Lifecycle::FromParent(Stream_->Identity), .StartOnSubmit = true};
            const auto Started = Stream_->Tasks->SpawnTracked(std::move(Request), Finish(Root_, Stream_));
            if (!Started)
            {
                Root_->RecordTerminalFailure(Started.error());
                Root_->Stop();
            }
        }
        std::shared_ptr<State> Root_;
        std::shared_ptr<StreamState> Stream_;
        std::vector<std::byte> Pending_;
        std::size_t Offset_{0};
        bool Closed_{false};
    };
}
