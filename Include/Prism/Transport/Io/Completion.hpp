/** @file Completion.hpp @brief 正式结果及 Asio 关联属性的窄完成适配器。 */
#pragma once
#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Compatible.hpp>

#include <boost/asio/any_completion_handler.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/associated_allocator.hpp>
#include <boost/asio/associated_cancellation_slot.hpp>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/bind_allocator.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/detail/config.hpp>
#include <boost/asio/recycling_allocator.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <exception>
#include <limits>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>
namespace Prism::Transport::Detail
{
    /** @brief 只在Asio ABI边界导出error_code；Native存在时保持原category/value。 */
    [[nodiscard]] auto ToAsioFailure(const Prism::Fault::Failure& Failure) -> boost::system::error_code;
    /** @brief 真实关联 allocator 值的共享所有者；不暴露 any_completion_handler 的 impl 代理。 */
    class CompletionAllocatorMaterial
    {
    public:
        virtual ~CompletionAllocatorMaterial() = default;
        virtual auto Allocate(std::size_t Size, std::size_t Alignment) -> void* = 0;
        virtual auto Deallocate(void* Pointer) noexcept -> void = 0;
        [[nodiscard]] virtual auto Type() const noexcept -> const void* = 0;
        [[nodiscard]] virtual auto IsEqual(const CompletionAllocatorMaterial& Other) const noexcept
            -> bool = 0;
        [[nodiscard]] virtual auto Compare(const void* Allocator) const noexcept -> bool = 0;
    };
    template <class Allocator>
    [[nodiscard]] inline auto CompletionAllocatorTypeToken() noexcept -> const void*
    {
        static const std::byte Token{};
        return &Token;
    }
    /** @brief 材料模型持有关联 byte-rebind allocator；分配头保存原分配实例与 fancy pointer。 */
    template <class Allocator>
    class CompletionAllocatorMaterialModel final : public CompletionAllocatorMaterial
    {
        using ByteAllocator = typename std::allocator_traits<Allocator>::template rebind_alloc<std::byte>;
        using ByteTraits = std::allocator_traits<ByteAllocator>;
        using BytePointer = typename ByteTraits::pointer;
        using ByteSize = typename ByteTraits::size_type;
        struct AllocationHeader final
        {
            ByteAllocator OwnerAllocator;
            BytePointer Original;
            ByteSize Count;
            AllocationHeader(ByteAllocator&& AllocatorValue, BytePointer&& OriginalValue,
                ByteSize AllocationCount) noexcept
                : OwnerAllocator(std::move(AllocatorValue)), Original(std::move(OriginalValue)),
                  Count(AllocationCount)
            {
            }
        };

    public:
        explicit CompletionAllocatorMaterialModel(Allocator Value)
            : Allocator_(ByteAllocator(std::move(Value)))
        {
        }
        auto Allocate(std::size_t Size, std::size_t Alignment) -> void* override
        {
            const auto ActualSize = std::max(Size, std::size_t{1});
            const auto ActualAlignment = std::max(Alignment, alignof(AllocationHeader));
            constexpr auto HeaderSize = sizeof(AllocationHeader);
            const auto Maximum = std::numeric_limits<std::size_t>::max();
            if (ActualAlignment - 1 > Maximum - HeaderSize ||
                ActualSize > Maximum - HeaderSize - (ActualAlignment - 1))
                throw std::bad_array_new_length();
            const auto Count = ActualSize + HeaderSize + ActualAlignment - 1;
            const auto AllocationCount = static_cast<ByteSize>(Count);
            if (static_cast<std::size_t>(AllocationCount) != Count)
                throw std::bad_array_new_length();
            ByteAllocator AllocatorValue(Allocator_);
            auto Original = ByteTraits::allocate(AllocatorValue, AllocationCount);
            std::byte* Aligned = nullptr;
            try
            {
                void* Candidate = std::addressof(*Original) + HeaderSize;
                auto Space = Count - HeaderSize;
                Aligned = static_cast<std::byte*>(std::align(ActualAlignment, ActualSize, Candidate, Space));
            }
            catch (...)
            {
                ByteTraits::deallocate(AllocatorValue, std::move(Original), AllocationCount);
                throw;
            }
            if (!Aligned)
            {
                ByteTraits::deallocate(AllocatorValue, std::move(Original), AllocationCount);
                throw std::bad_alloc();
            }
            auto* Header = reinterpret_cast<AllocationHeader*>(Aligned) - 1;
            std::construct_at(Header, std::move(AllocatorValue), std::move(Original), AllocationCount);
            return Aligned;
        }
        auto Deallocate(void* Pointer) noexcept -> void override
        {
            auto* Header = static_cast<AllocationHeader*>(Pointer) - 1;
            ByteAllocator AllocatorValue(std::move(Header->OwnerAllocator));
            BytePointer Original(std::move(Header->Original));
            const auto Count = Header->Count;
            std::destroy_at(Header);
            ByteTraits::deallocate(AllocatorValue, std::move(Original), Count);
        }
        [[nodiscard]] auto Type() const noexcept -> const void* override
        {
            return CompletionAllocatorTypeToken<ByteAllocator>();
        }
        [[nodiscard]] auto IsEqual(const CompletionAllocatorMaterial& Other) const noexcept -> bool override
        {
            if (Type() != Other.Type())
                return false;
            return Other.Compare(&Allocator_);
        }
        [[nodiscard]] auto Compare(const void* AllocatorValue) const noexcept -> bool override
        {
            return Allocator_ == *static_cast<const ByteAllocator*>(AllocatorValue);
        }

    private:
        ByteAllocator Allocator_;
    };
    template <class Type>
    struct IsAsioRecyclingAllocator : std::false_type
    {
    };
    template <class Type>
    struct IsAsioRecyclingAllocator<boost::asio::recycling_allocator<Type>> : std::true_type
    {
    };
    enum class CompletionAllocatorMode : unsigned char
    {
        Invalid,
        Recycling,
        Material
    };
    /** @brief 默认模式直接持 Asio recycling allocator；自定义模式共享真实 allocator 材料 owner。 */
    template <class Type>
    class CompletionAllocator final
    {
    public:
        using value_type = Type;
        using is_always_equal = std::false_type;
        template <class Other>
        struct rebind
        {
            using other = CompletionAllocator<Other>;
        };
        CompletionAllocator() noexcept = default;
        explicit CompletionAllocator(std::shared_ptr<CompletionAllocatorMaterial> Material) noexcept
            : Material_(std::move(Material))
        {
            if (Material_)
            {
                Mode_ = CompletionAllocatorMode::Material;
            }
        }
        template <class Allocator>
            requires IsAsioRecyclingAllocator<std::remove_cvref_t<Allocator>>::value
        explicit CompletionAllocator(Allocator&& Value) noexcept
            : Mode_(CompletionAllocatorMode::Recycling), RecyclingAllocator_(std::forward<Allocator>(Value))
        {
        }
        CompletionAllocator(const CompletionAllocator&) noexcept = default;
        auto operator=(const CompletionAllocator&) noexcept -> CompletionAllocator& = default;
        CompletionAllocator(CompletionAllocator&& Value) noexcept
            : Mode_(Value.Mode_), RecyclingAllocator_(Value.RecyclingAllocator_),
              Material_(std::move(Value.Material_))
        {
            Value.Mode_ = CompletionAllocatorMode::Invalid;
        }
        auto operator=(CompletionAllocator&& Value) noexcept -> CompletionAllocator&
        {
            if (this != &Value)
            {
                Material_.reset();
                Mode_ = Value.Mode_;
                RecyclingAllocator_ = Value.RecyclingAllocator_;
                Material_ = std::move(Value.Material_);
                Value.Mode_ = CompletionAllocatorMode::Invalid;
            }
            return *this;
        }
        template <class Other>
        CompletionAllocator(const CompletionAllocator<Other>& Value) noexcept
            : Mode_(Value.Mode_), RecyclingAllocator_(Value.RecyclingAllocator_), Material_(Value.Material_)
        {
        }
        [[nodiscard]] auto allocate(std::size_t Count) -> Type*
        {
            if (Count > std::numeric_limits<std::size_t>::max() / sizeof(Type))
                throw std::bad_array_new_length();
            if (Mode_ == CompletionAllocatorMode::Recycling)
            {
                constexpr auto Maximum = static_cast<std::size_t>(std::numeric_limits<std::ptrdiff_t>::max());
                constexpr auto AsioOverhead = std::size_t{8};
                constexpr auto Alignment = std::max(static_cast<std::size_t>(alignof(Type)),
                    static_cast<std::size_t>(BOOST_ASIO_DEFAULT_ALIGN));
                const auto Size = Count * sizeof(Type);
                if (Alignment - 1 > Maximum - AsioOverhead || Size > Maximum - AsioOverhead - (Alignment - 1))
                    throw std::bad_array_new_length();
                return RecyclingAllocator_.allocate(Count);
            }
            if (Mode_ != CompletionAllocatorMode::Material || !Material_)
                throw std::bad_array_new_length();
            auto Material = Material_;
            return static_cast<Type*>(Material->Allocate(Count * sizeof(Type), alignof(Type)));
        }
        auto deallocate(Type* Pointer, std::size_t Count) noexcept -> void
        {
            if (!Pointer)
                return;
            if (Mode_ == CompletionAllocatorMode::Recycling)
            {
                RecyclingAllocator_.deallocate(Pointer, Count);
                return;
            }
            if (Mode_ != CompletionAllocatorMode::Material || !Material_)
                std::terminate();
            auto Material = Material_;
            Material->Deallocate(Pointer);
        }
        template <class Other>
        [[nodiscard]] auto operator==(const CompletionAllocator<Other>& Value) const noexcept -> bool
        {
            if (Mode_ != Value.Mode_)
                return false;
            if (Mode_ != CompletionAllocatorMode::Material)
                return true;
            if (Material_ == Value.Material_)
                return true;
            return Material_ && Value.Material_ && Material_->IsEqual(*Value.Material_);
        }
        template <class Other>
        [[nodiscard]] auto operator!=(const CompletionAllocator<Other>& Value) const noexcept -> bool
        {
            return !(*this == Value);
        }
        auto Swap(CompletionAllocator& Other) noexcept -> void
        {
            using std::swap;
            swap(Mode_, Other.Mode_);
            swap(RecyclingAllocator_, Other.RecyclingAllocator_);
            Material_.swap(Other.Material_);
        }

    private:
        template <class>
        friend class CompletionAllocator;
        CompletionAllocatorMode Mode_ = CompletionAllocatorMode::Invalid;
        [[no_unique_address]] boost::asio::recycling_allocator<Type> RecyclingAllocator_;
        std::shared_ptr<CompletionAllocatorMaterial> Material_;
    };
    template <class Type>
    struct IsCompletionAllocator : std::false_type
    {
    };
    template <class Type>
    struct IsCompletionAllocator<CompletionAllocator<Type>> : std::true_type
    {
    };
    template <class Allocator>
    struct IsAnyCompletionHandlerAllocator : std::false_type
    {
    };
    template <class Type, class... Signatures>
    struct IsAnyCompletionHandlerAllocator<boost::asio::any_completion_handler_allocator<Type, Signatures...>>
        : std::true_type
    {
    };
    /** @brief 在 typed handler 尚存时复制关联 allocator；精确 Asio recycling 类型直接按值保留。 */
    template <class Allocator>
    [[nodiscard]] auto CaptureCompletionAllocator(Allocator Value) -> CompletionAllocator<std::byte>
    {
        using ValueType = std::remove_cvref_t<Allocator>;
        if constexpr (IsCompletionAllocator<ValueType>::value)
        {
            return CompletionAllocator<std::byte>(Value);
        }
        else if constexpr (IsAsioRecyclingAllocator<ValueType>::value)
        {
            return CompletionAllocator<std::byte>(std::move(Value));
        }
        else
        {
            static_assert(!IsAnyCompletionHandlerAllocator<ValueType>::value,
                "typed handler is required; any_completion_handler allocator is a non-owning proxy");
            ValueType Stored(std::move(Value));
            return CompletionAllocator<std::byte>(
                std::allocate_shared<CompletionAllocatorMaterialModel<ValueType>>(Stored, Stored));
        }
    }
    /** @brief 一次性 IoResult completion，allocator_type 独立持有关联材料及异步调用帧。 */
    class IoCompletion final
    {
        using ErasedHandler = boost::asio::any_completion_handler<void(Prism::IoResult)>;

    public:
        using executor_type = boost::asio::associated_executor_t<ErasedHandler>;
        using allocator_type = CompletionAllocator<std::byte>;
        using cancellation_slot_type = boost::asio::associated_cancellation_slot_t<ErasedHandler>;
        IoCompletion() noexcept = default;
        IoCompletion(IoCompletion&& Value) noexcept;
        auto operator=(IoCompletion&& Value) noexcept -> IoCompletion&;
        /** @brief 丢弃未调用的完成体；先退役 handler 及其分配，再释放材料 owner。 */
        auto operator=(std::nullptr_t) noexcept -> IoCompletion&;
        IoCompletion(const IoCompletion&) = delete;
        auto operator=(const IoCompletion&) -> IoCompletion& = delete;
        template <class Handler>
            requires(!std::same_as<std::remove_cvref_t<Handler>, IoCompletion> &&
                        !std::same_as<std::remove_cvref_t<Handler>, ErasedHandler>)
        IoCompletion(Handler&& Callback)
            : Allocator_(CaptureCompletionAllocator(
                  boost::asio::get_associated_allocator(Callback, boost::asio::recycling_allocator<void>()))),
              Handler_(boost::asio::bind_allocator(Allocator_, std::forward<Handler>(Callback)))
        {
        }
        IoCompletion(ErasedHandler&&) = delete;
        [[nodiscard]] explicit operator bool() const noexcept;
        [[nodiscard]] auto operator!() const noexcept -> bool;
        [[nodiscard]] auto get_executor() const noexcept -> executor_type;
        [[nodiscard]] auto get_allocator() const noexcept -> allocator_type;
        [[nodiscard]] auto get_cancellation_slot() const noexcept -> cancellation_slot_type;
        auto operator()(Prism::IoResult Result) -> void;
        auto Swap(IoCompletion& Other) noexcept -> void;

    private:
        allocator_type Allocator_;
        ErasedHandler Handler_;
    };
    /**
     * @brief 用户 completion 的关联属性基座，原样转交 executor、allocator 与 cancellation slot。
     * @details 输入所有权：构造按值接管 Handler；不拥有 handler 引用的 buffer 或 frame。
     *          输出与错误：本基类不调用 Handler，具体交付由派生类型决定。
     *          取消：原样转交用户关联 slot；QueuedCompletion 可在此基础上建立子取消状态。
     *          半关闭：不触及传输方向；最终关闭者：不关闭资源，只随 Handler 析构释放回调。
     *          executor：不硬编码执行域，三项关联属性均由实际 Handler 提供。
     */
    template <class Handler>
    class AssociatedCompletion
    {
    public:
        using executor_type = boost::asio::associated_executor_t<Handler>;
        using allocator_type = boost::asio::associated_allocator_t<Handler>;
        using cancellation_slot_type = boost::asio::associated_cancellation_slot_t<Handler>;
        explicit AssociatedCompletion(Handler Completion) : Handler_(std::move(Completion))
        {
        }
        [[nodiscard]] auto get_executor() const noexcept -> executor_type
        {
            return boost::asio::get_associated_executor(Handler_);
        }
        [[nodiscard]] auto get_allocator() const noexcept -> allocator_type
        {
            return boost::asio::get_associated_allocator(Handler_);
        }
        [[nodiscard]] auto get_cancellation_slot() const noexcept -> cancellation_slot_type
        {
            return boost::asio::get_associated_cancellation_slot(Handler_);
        }

    protected:
        Handler Handler_;
    };
    /**
     * @brief 把 Asio error/bytes 形状转换为同次领域 IoResult。
     * @details 输入所有权：按值接管 IoCompletion，不拥有 buffer；输出保留实际字节数与原生错误，
     *          无字节数的完成使用零，失败不抹去已完成字节。
     *          取消沿用户 cancellation slot 交给 Asio；operation_aborted 按原生映射为 Canceled。
     *          本类型不触及半关闭或最终关闭；leaf 载体仍是 socket 的关闭 owner。
     * @note 恰一次由 Asio engine 与 TrackedCompletion 保证，错误与字节数保持同次交付。
     */
    class NativeCompletion final : public AssociatedCompletion<IoCompletion>
    {
    public:
        explicit NativeCompletion(IoCompletion Handler);
        auto operator()(boost::system::error_code Error) -> void;
        auto operator()(boost::system::error_code Error, std::size_t Bytes) -> void;
    };
    /**
     * @brief 携带已完成结果的拥有型交付体，本身只在队列工作帧中调用。
     * @details post 的目标 executor 由外层 QueueExecutor 明确提供；Asio 内部
     *          work dispatcher 再读取本体继承的关联 executor、allocator 与取消槽，
     *          把本体投递到用户完成域。因此 any_completion_executor 不会被拿去
     *          require blocking.never，空载体、取消和预约拒绝也不会同步重入 handler。
     */
    class ResultDelivery final : public AssociatedCompletion<IoCompletion>
    {
    public:
        ResultDelivery(IoCompletion Handler, Prism::IoResult Result);
        auto operator()() -> void;

    private:
        Prism::IoResult Result_;
    };
    /** @brief 借用结束于 handler 返回；错误结果同样经真实 owner 队列异步交付一次。 */
    auto PostResult(boost::asio::any_io_executor QueueExecutor, IoCompletion Handler, Prism::IoResult Result)
        -> void;
    /**
     * @brief 把中间状态机钉在原 executor，并将最终完成投回用户关联 executor。
     * @details 输入所有权：按值持有原 executor 与 completion，不拥有 buffer。
     *          输出与错误：经 PostResult 交付 IoResult，Code 与 Native 不折叠。
     *          取消：继承用户 allocator 与 cancellation slot，不重写用户取消。
     *          半关闭与最终关闭：均不执行或接管资源关闭。
     *          executor：先排入指定原域，再由用户 completion 的关联 executor 接收结果。
     */
    class OriginalCompletion final : public AssociatedCompletion<IoCompletion>
    {
    public:
        using executor_type = boost::asio::any_io_executor;
        OriginalCompletion(executor_type Executor, IoCompletion Handler);
        [[nodiscard]] auto get_executor() const noexcept -> executor_type;
        auto operator()(Prism::IoResult Result) -> void;

    private:
        executor_type Executor_;
    };
    /**
     * @brief 在进入队列前挂上自有 total-cancellation 状态，并提供排队前快照。
     * @details 输入所有权：按值持有 completion 与取消状态，不拥有 buffer；输出时同步转交 IoResult。
     *          恰一次与异步性由实际发起链负责；取消槽覆盖基类 slot 为可启用 total cancellation 的子槽。
     *          快照用于决定是否发起 I/O；发起后的完成时点仍由 Asio 决定。
     *          本类型不触及半关闭或最终关闭，executor、allocator 仍来自用户 handler。
     */
    class QueuedCompletion final : public AssociatedCompletion<IoCompletion>
    {
    public:
        using cancellation_slot_type = boost::asio::cancellation_slot;
        explicit QueuedCompletion(IoCompletion Handler);
        [[nodiscard]] auto get_cancellation_slot() const noexcept -> cancellation_slot_type;
        [[nodiscard]] auto Cancellation() const noexcept -> boost::asio::cancellation_state;
        auto operator()(Prism::IoResult Result) -> void;

    private:
        boost::asio::cancellation_state Cancellation_;
    };
    /** @brief co_composed 显式取消检查；普通取消由实际操作值返回，不由异常退出帧。 */
    template <class State>
    auto ConfigureIo(State& Operation) -> void
    {
        Operation.throw_if_cancelled(false);
        Operation.reset_cancellation_state(boost::asio::enable_total_cancellation());
    }
} // namespace Prism::Transport::Detail
