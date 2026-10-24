/** @file TlsStream.cpp @brief 公开 TLS facade 与私有 engine 的 owning 转发。 */
#include <Prism/Transport/TlsStream.hpp>

#include <Prism/Transport/Detail/IoActivity.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Transport/Detail/TlsEngine.hpp>

#include <boost/asio/buffer.hpp>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/system/error_code.hpp>

#include <memory>
#include <utility>

namespace Prism::Transport::Detail
{
    namespace
    {
        class TlsResultQueue final : public AssociatedCompletion<IoCompletion>
        {
        public:
            explicit TlsResultQueue(TlsResultRequest Request)
                : AssociatedCompletion(std::move(Request.Handler)),
                  Carrier_(std::move(Request.Carrier)),
                  Result_(std::move(Request.Result))
            {
            }

            auto operator()() -> void
            {
                std::move(this->Handler_)(std::move(Result_));
            }

        private:
            std::shared_ptr<TlsStream> Carrier_;
            Prism::IoResult Result_;
        };
    } // namespace

    auto PostTlsResult(TlsResultRequest Request) -> void
    {
        if (!Request.Handler) return;
        const auto QueueTarget = Request.QueueExecutor;
        TlsResultQueue Delivery(std::move(Request));
        Net::post(QueueTarget, std::move(Delivery));
    }

    TlsEngine::TlsEngine(Connector Next, Net::ssl::context& Context)
        : Next_(std::move(Next)), Executor_(Net::make_strand(Next_.get_executor())),
          Core_(Context.native_handle(), Executor_),
          Activity_(std::make_shared<IoActivity>(
              Executor_, IoActivity::RetirementPolicy::OperationsDrained))
    {
    }

    TlsEngine::~TlsEngine() = default;

    auto TlsEngine::Activity() const noexcept
        -> std::shared_ptr<Prism::Contract::CarrierActivity>
    {
        return Activity_;
    }

    auto TlsEngine::IsIdle() const noexcept -> bool
    {
        return Activity_->IsIdle();
    }

    auto TlsEngine::get_executor() const noexcept -> executor_type
    {
        return Executor_;
    }

    auto TlsEngine::next_layer() noexcept -> Connector&
    {
        return Next_;
    }

    auto TlsEngine::next_layer() const noexcept -> const Connector&
    {
        return Next_;
    }

    auto TlsEngine::lowest_layer() noexcept -> Prism::Transmission&
    {
        return Next_.lowest_layer();
    }

    auto TlsEngine::native_handle() noexcept -> SSL*
    {
        return Core_.engine_.native_handle();
    }

    auto TlsEngine::ReadSome(
        std::shared_ptr<TlsStream> Carrier, std::span<std::byte> Input,
        IoCompletion Handler) -> void
    {
        using Operation = TlsDataOperation<Net::mutable_buffer, true>;
        Initiate<Operation, false>(
            std::move(Carrier),
            Operation(Net::buffer(Input.data(), Input.size())),
            std::move(Handler));
    }

    auto TlsEngine::ReadSomeBound(
        std::shared_ptr<TlsStream> Carrier, std::span<std::byte> Input,
        IoCompletion Handler) -> void
    {
        using Operation = TlsDataOperation<Net::mutable_buffer, true>;
        Initiate<Operation, true>(
            std::move(Carrier),
            Operation(Net::buffer(Input.data(), Input.size())),
            std::move(Handler));
    }

    auto TlsEngine::WriteSome(
        std::shared_ptr<TlsStream> Carrier, std::span<const std::byte> Input,
        IoCompletion Handler) -> void
    {
        using Operation = TlsDataOperation<Net::const_buffer, false>;
        Initiate<Operation, false>(
            std::move(Carrier),
            Operation(Net::buffer(Input.data(), Input.size())),
            std::move(Handler));
    }

    auto TlsEngine::WriteSomeBound(
        std::shared_ptr<TlsStream> Carrier, std::span<const std::byte> Input,
        IoCompletion Handler) -> void
    {
        using Operation = TlsDataOperation<Net::const_buffer, false>;
        Initiate<Operation, true>(
            std::move(Carrier),
            Operation(Net::buffer(Input.data(), Input.size())),
            std::move(Handler));
    }

    auto TlsEngine::WriteShutdown(
        std::shared_ptr<TlsStream> Carrier, IoCompletion Handler) -> void
    {
        Initiate<TlsWriteShutdownOperation, false>(
            std::move(Carrier), TlsWriteShutdownOperation{}, std::move(Handler));
    }

    auto TlsEngine::WriteShutdownBound(
        std::shared_ptr<TlsStream> Carrier, IoCompletion Handler) -> void
    {
        Initiate<TlsWriteShutdownOperation, true>(
            std::move(Carrier), TlsWriteShutdownOperation{}, std::move(Handler));
    }

    auto TlsEngine::Handshake(
        std::shared_ptr<TlsStream> Carrier,
        const Net::ssl::stream_base::handshake_type Side,
        IoCompletion Handler) -> void
    {
        Initiate<SslDetail::handshake_op, true>(
            std::move(Carrier), SslDetail::handshake_op(Side), std::move(Handler));
    }

    auto TlsEngine::Shutdown(
        std::shared_ptr<TlsStream> Carrier, IoCompletion Handler) -> void
    {
        Initiate<SslDetail::shutdown_op, true>(
            std::move(Carrier), SslDetail::shutdown_op{}, std::move(Handler));
    }
} // namespace Prism::Transport::Detail

namespace Prism::Transport
{
    TlsStream::TlsStream(Connector Next, Net::ssl::context& Context)
        : Engine_(std::make_unique<Detail::TlsEngine>(std::move(Next), Context))
    {
    }

    TlsStream::~TlsStream() = default;

    auto TlsStream::ToAsioError(const Prism::Fault::Failure& Failure)
        -> boost::system::error_code
    {
        return Detail::ToAsioFailure(Failure);
    }

    auto TlsStream::PostAsioResult(
        executor_type QueueExecutor,
        Prism::Transmission::Completion Handler,
        Prism::IoResult Result) -> void
    {
        Detail::PostTlsResult({std::move(QueueExecutor), {},
                               std::move(Handler), std::move(Result)});
    }

    auto TlsStream::Activity() const noexcept
        -> std::shared_ptr<Prism::Contract::CarrierActivity>
    {
        return Engine_->Activity();
    }

    auto TlsStream::IsIdle() const noexcept -> bool
    {
        return Engine_->IsIdle();
    }

    auto TlsStream::get_executor() const noexcept -> executor_type
    {
        return Engine_->get_executor();
    }

    auto TlsStream::next_layer() noexcept -> Connector&
    {
        return Engine_->next_layer();
    }

    auto TlsStream::next_layer() const noexcept -> const Connector&
    {
        return Engine_->next_layer();
    }

    auto TlsStream::lowest_layer() noexcept -> Prism::Transmission&
    {
        return Engine_->lowest_layer();
    }

    auto TlsStream::native_handle() noexcept -> SSL*
    {
        return Engine_->native_handle();
    }

    auto TlsStream::ReadSome(
        std::span<std::byte> Input, Prism::Transmission::Completion Handler) -> void
    {
        auto Owner = weak_from_this().lock();
        if (!Owner)
        {
            Detail::PostTlsResult({get_executor(), {}, std::move(Handler),
                {0, {Prism::Fault::Code::InvalidArgument}}});
            return;
        }
        Engine_->ReadSome(std::move(Owner), Input, std::move(Handler));
    }

    auto TlsStream::WriteSome(
        std::span<const std::byte> Input, Prism::Transmission::Completion Handler) -> void
    {
        auto Owner = weak_from_this().lock();
        if (!Owner)
        {
            Detail::PostTlsResult({get_executor(), {}, std::move(Handler),
                {0, {Prism::Fault::Code::InvalidArgument}}});
            return;
        }
        Engine_->WriteSome(std::move(Owner), Input, std::move(Handler));
    }

    auto TlsStream::WriteShutdown(Prism::Transmission::Completion Handler) -> void
    {
        auto Owner = weak_from_this().lock();
        if (!Owner)
        {
            Detail::PostTlsResult({get_executor(), {}, std::move(Handler),
                {0, {Prism::Fault::Code::InvalidArgument}}});
            return;
        }
        Engine_->WriteShutdown(std::move(Owner), std::move(Handler));
    }

    auto TlsStream::StartReadSome(
        std::shared_ptr<TlsStream> Owner, std::span<std::byte> Input,
        Prism::Transmission::Completion Handler) -> void
    {
        Engine_->ReadSomeBound(std::move(Owner), Input, std::move(Handler));
    }

    auto TlsStream::StartWriteSome(
        std::shared_ptr<TlsStream> Owner, std::span<const std::byte> Input,
        Prism::Transmission::Completion Handler) -> void
    {
        Engine_->WriteSomeBound(std::move(Owner), Input, std::move(Handler));
    }

    auto TlsStream::StartWriteShutdown(
        std::shared_ptr<TlsStream> Owner, Prism::Transmission::Completion Handler) -> void
    {
        Engine_->WriteShutdownBound(std::move(Owner), std::move(Handler));
    }

    auto TlsStream::StartHandshake(
        std::shared_ptr<TlsStream> Owner,
        const Net::ssl::stream_base::handshake_type Side,
        Prism::Transmission::Completion Handler) -> void
    {
        Engine_->Handshake(std::move(Owner), Side, std::move(Handler));
    }

    auto TlsStream::StartShutdown(
        std::shared_ptr<TlsStream> Owner, Prism::Transmission::Completion Handler) -> void
    {
        Engine_->Shutdown(std::move(Owner), std::move(Handler));
    }
} // namespace Prism::Transport
