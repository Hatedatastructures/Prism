/** @file IoCompletion.cpp @brief 类型擦除完成结果的交付实现。 */
#include <Prism/Transport/Io/Completion.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <system_error>

namespace Prism::Transport::Detail
{
    auto ToAsioFailure(const Prism::Fault::Failure& Failure) -> boost::system::error_code
    {
        if (Failure.Native)
        {
            const auto& Native = Failure.Native;
            if (Native.category() == Prism::ErrorCategory())
                return Prism::make_error_code(static_cast<Prism::Error>(Native.value()));
            if (Native.category() == Prism::Fault::Category())
                return boost::system::make_error_code(static_cast<Prism::Fault::Code>(Native.value()));
            if (Native.category() == std::generic_category())
                return {Native.value(), boost::system::generic_category()};
            if (Native.category() == std::system_category())
                return {Native.value(), boost::system::system_category()};
            return boost::system::error_code(Native);
        }
        if (Failure.Code == Prism::Fault::Code::Success) return {};
        if (Failure.Code == Prism::Fault::Code::Eof) return boost::asio::error::eof;
        if (Failure.Code == Prism::Fault::Code::Canceled) return boost::asio::error::operation_aborted;
        if (Failure.Code == Prism::Fault::Code::Timeout) return boost::asio::error::timed_out;
        return boost::system::make_error_code(Failure.Code);
    }

    IoCompletion::IoCompletion(IoCompletion&& Value) noexcept
        : Allocator_(std::move(Value.Allocator_)), Handler_(std::move(Value.Handler_))
    {
        Value.Allocator_ = allocator_type{};
    }

    auto IoCompletion::operator=(IoCompletion&& Value) noexcept -> IoCompletion&
    {
        if (this != &Value)
        {
            Handler_ = nullptr;
            Allocator_ = std::move(Value.Allocator_);
            Handler_ = std::move(Value.Handler_);
            Value.Allocator_ = allocator_type{};
        }
        return *this;
    }

    auto IoCompletion::operator=(std::nullptr_t) noexcept -> IoCompletion&
    {
        Handler_ = nullptr;
        Allocator_ = allocator_type{};
        return *this;
    }

    IoCompletion::operator bool() const noexcept
    {
        return static_cast<bool>(Handler_);
    }

    auto IoCompletion::operator!() const noexcept -> bool
    {
        return !Handler_;
    }

    auto IoCompletion::get_executor() const noexcept -> executor_type
    {
        return boost::asio::get_associated_executor(Handler_);
    }

    auto IoCompletion::get_allocator() const noexcept -> allocator_type
    {
        return Allocator_;
    }

    auto IoCompletion::get_cancellation_slot() const noexcept -> cancellation_slot_type
    {
        return boost::asio::get_associated_cancellation_slot(Handler_);
    }

    auto IoCompletion::operator()(Prism::IoResult Result) -> void
    {
        std::move(Handler_)(std::move(Result));
    }

    auto IoCompletion::Swap(IoCompletion& Other) noexcept -> void
    {
        Allocator_.Swap(Other.Allocator_);
        Handler_.swap(Other.Handler_);
    }

    NativeCompletion::NativeCompletion(IoCompletion Handler)
        : AssociatedCompletion(std::move(Handler))
    {
    }

    auto NativeCompletion::operator()(boost::system::error_code Error) -> void
    {
        std::move(Handler_)(Prism::IoResult{
            0, Prism::Fault::FromNative(static_cast<std::error_code>(Error))});
    }

    auto NativeCompletion::operator()(boost::system::error_code Error, std::size_t Bytes) -> void
    {
        std::move(Handler_)(Prism::IoResult{
            Bytes, Prism::Fault::FromNative(static_cast<std::error_code>(Error))});
    }

    OriginalCompletion::OriginalCompletion(executor_type Executor, IoCompletion Handler)
        : AssociatedCompletion(std::move(Handler)), Executor_(std::move(Executor))
    {
    }

    auto OriginalCompletion::get_executor() const noexcept -> executor_type
    {
        return Executor_;
    }

    auto OriginalCompletion::operator()(Prism::IoResult Result) -> void
    {
        PostResult(Executor_, std::move(Handler_), std::move(Result));
    }

    QueuedCompletion::QueuedCompletion(IoCompletion Handler)
        : AssociatedCompletion(std::move(Handler)),
          Cancellation_(boost::asio::get_associated_cancellation_slot(Handler_),
              boost::asio::enable_total_cancellation())
    {
    }

    auto QueuedCompletion::get_cancellation_slot() const noexcept -> cancellation_slot_type
    {
        return Cancellation_.slot();
    }

    auto QueuedCompletion::Cancellation() const noexcept -> boost::asio::cancellation_state
    {
        return Cancellation_;
    }

    auto QueuedCompletion::operator()(Prism::IoResult Result) -> void
    {
        std::move(Handler_)(Result);
    }

    ResultDelivery::ResultDelivery(IoCompletion Handler, Prism::IoResult Result)
        : AssociatedCompletion(std::move(Handler)), Result_(std::move(Result))
    {
    }

    auto ResultDelivery::operator()() -> void
    {
        std::move(Handler_)(std::move(Result_));
    }

    auto PostResult(boost::asio::any_io_executor QueueExecutor,
        IoCompletion Handler, Prism::IoResult Result) -> void
    {
        if (!Handler) return;
        boost::asio::post(QueueExecutor, ResultDelivery(std::move(Handler), std::move(Result)));
    }
} // namespace Prism::Transport::Detail
