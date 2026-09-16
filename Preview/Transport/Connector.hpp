/**
 * @file Connector.hpp
 * @brief Socket 异步 IO 适配器
 * @details 统一 TCP 和 UDP 的异步读写接口，将 Transmission
 * 适配为 Boost.Asio 的 AsyncReadStream/AsyncWriteStream
 * 概念。支持注入预读数据，避免协议检测时丢失数据。
 * @note 预读数据注入必须在协议握手之前完成。
 * @warning 预读数据注入时机不当可能导致协议解析失败。
 */

#pragma once

#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <vector>
#include <utility>

namespace Preview::Transport {

    namespace Net = boost::asio;

    /**
     * @class Connector
     * @brief Transmission 适配器
     * @details 将 Transmission 接口适配为 Boost.Asio 的
     * AsyncReadStream/AsyncWriteStream 概念。内部使用
     * shared_ptr 持有 Transmission，确保异步操作期间
     * 传输对象不会被提前释放。支持注入预读数据，
     * 避免协议检测阶段已读取的数据丢失。
     * @note 预读数据注入必须在协议握手之前完成。
     * @warning 预读数据注入时机不当可能导致协议解析失败。
     * @throws std::bad_alloc 如果内存分配失败
     */
    class Connector final
    {
    public:
        using ExecutorType = Net::any_io_executor;
        using executor_type = Net::any_io_executor;
        using TransmissionPtr = Preview::SharedTransmission;
        using lowest_layer_type = Transmission;

        [[nodiscard]] auto lowest_layer() noexcept -> Transmission & { return *Trans_; }
        [[nodiscard]] auto lowest_layer() const noexcept -> const Transmission & { return *Trans_; }

        /**
         * @brief 构造函数（传输层指针 + 预读数据）
         * @details 使用传输层指针和可选的预读数据构造适配器。
         * 预读数据将在首次 async_read_some 调用时优先返回，
         * 避免协议检测阶段已读取的数据丢失。
         * @param trans 传输层对象指针，所有权将被转移
         * @param preread 预读数据切片，默认为空
         */
        explicit Connector(TransmissionPtr TransmissionObject, std::span<const std::byte> Preread = {})
            : Trans_(std::move(TransmissionObject))
        {
            if (!Preread.empty())
            {
                PrereadBuffer_.assign(Preread.begin(), Preread.end());
            }
        }

        /**
         * @brief 移动构造函数
         * @details 转移传输层指针、预读缓冲区和偏移量的所有权。
         * 移动后源对象的偏移量被重置为零。
         * @param other 要移动的适配器对象
         */
        Connector(Connector &&Other) noexcept
            : Trans_(std::move(Other.Trans_)), PrereadBuffer_(std::move(Other.PrereadBuffer_)),
              PrereadOffset_(Other.PrereadOffset_)
        {
            Other.PrereadOffset_ = 0;
        }

        /**
         * @brief 移动赋值运算符
         * @details 转移传输层指针、预读缓冲区和偏移量的所有权。
         * 移动后源对象的偏移量被重置为零。防止自赋值。
         * @param other 要移动的适配器对象
         * @return Connector& 当前对象的引用
         */
        auto operator=(Connector &&Other) noexcept -> Connector &
        {
            if (this != &Other)
            {
                Trans_ = std::move(Other.Trans_);
                PrereadBuffer_ = std::move(Other.PrereadBuffer_);
                PrereadOffset_ = Other.PrereadOffset_;
                Other.PrereadOffset_ = 0;
            }
            return *this;
        }

        /**
         * @brief 获取执行器
         * @details 返回底层传输层关联的执行器，满足 Boost.Asio 的
         * AsyncStream 概念要求。
         * @return ExecutorType 执行器对象
         */
        [[nodiscard]] auto get_executor() -> ExecutorType
        {
            return Trans_->Executor();
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         * @return 底层 Transmission 指针
         */
        [[nodiscard]] auto NextLayer() noexcept -> Transmission *
        {
            return Trans_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 底层 Transmission 指针
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission *
        {
            return Trans_.get();
        }

        /**
         * @brief 获取执行器
         * @details 委托给 get_executor()，提供便捷的执行器访问。
         * @return ExecutorType 执行器对象
         */
        [[nodiscard]] auto Executor() -> ExecutorType
        {
            return get_executor();
        }

        /**
         * @brief 适配 async_read_some
         * @details 将 Boost.Asio 的 async_read_some 调用适配到 Transmission 接口。
         * 如果存在未消费的预读数据，优先从预读缓冲区拷贝到用户缓冲区，
         * 避免额外的异步读取操作。预读数据消费完毕后委托给传输层。
         * @tparam MutableBufferSequence 可变缓冲区序列类型
         * @tparam CompletionToken 完成令牌类型（协程、回调等）
         * @param buffers 可变缓冲区序列，用于存储读取的数据
         * @param token 完成令牌，用于接收读取结果
         * @return 异步操作结果，类型取决于完成令牌
         */
        template <typename MutableBufferSequence, typename CompletionToken>
        [[maybe_unused]] auto async_read_some(const MutableBufferSequence &BufferSequence,
                                              CompletionToken &&CompletionTokenObject)
        {
            auto ReadBuffers = CollectMutableBuffers(BufferSequence);
            if (PrereadOffset_ < PrereadBuffer_.size())
            {
                const auto BytesToCopy = CopyToBuffers(
                    std::span<const std::byte>(PrereadBuffer_).subspan(PrereadOffset_), ReadBuffers);
                PrereadOffset_ += BytesToCopy;
                const auto Ex = Trans_->Executor();
                auto PrereadOperation = [Ex, BytesToCopy](auto &&Handler) mutable
                    {
                        PostCompletion(Ex, std::forward<decltype(Handler)>(Handler), {}, BytesToCopy);
                    };
                return Net::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(
                    std::move(PrereadOperation), CompletionTokenObject);
            }

            // 预读数据已耗尽：单一缓冲直接委托，多缓冲使用短生命周期聚合缓冲，
            // 完成后再按原序列回写，保持 Transmission 的连续 span 接口。
            auto ReadOperation =
                [TransmissionObject = Trans_, ReadBuffers = std::move(ReadBuffers)](auto &&Handler) mutable
                {
                    using HandlerType = std::decay_t<decltype(Handler)>;
                    auto State = std::make_shared<ReadState<HandlerType>>();
                    State->Trans = TransmissionObject;
                    State->Buffers = std::move(ReadBuffers);
                    State->Completion.emplace(std::forward<decltype(Handler)>(Handler));
                    for (const auto Buffer : State->Buffers)
                    {
                        State->Capacity += Buffer.size();
                    }
                    if (State->Capacity == 0)
                    {
                        auto Completion = std::move(*State->Completion);
                        State->Completion.reset();
                        PostCompletion(State->Trans->Executor(), std::move(Completion), {}, 0);
                        return;
                    }
                    if (State->Buffers.size() == 1)
                    {
                        const auto Buffer = State->Buffers.front();
                        const auto Span = std::span<std::byte>(
                            reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size());
                        auto CompleteOperation =
                            [State](boost::system::error_code Ec, const std::size_t N)
                        {
                            CompleteRead(State, std::move(Ec), N);
                        };
                        State->Trans->async_read_some(Span, std::move(CompleteOperation));
                        return;
                    }
                    State->Scratch.resize(State->Capacity);
                    State->UsesScratch = true;
                    auto CompleteOperation =
                        [State](boost::system::error_code Ec, const std::size_t N)
                    {
                        CompleteRead(State, std::move(Ec), N);
                    };
                    State->Trans->async_read_some(std::span<std::byte>(State->Scratch),
                                                  std::move(CompleteOperation));
                };
            return Net::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(
                std::move(ReadOperation), CompletionTokenObject);
        }

        /**
         * @brief 适配 async_write_some
         * @details 将 Boost.Asio 的 async_write_some 调用直接委托给传输层。
         * @tparam ConstBufferSequence 常量缓冲区序列类型
         * @tparam CompletionToken 完成令牌类型
         * @param buffers 常量缓冲区序列，包含要写入的数据
         * @param token 完成令牌，用于接收写入结果
         * @return 异步操作结果，类型取决于完成令牌
         */
        template <typename ConstBufferSequence, typename CompletionToken>
        auto async_write_some(const ConstBufferSequence &BufferSequence,
                              CompletionToken &&CompletionTokenObject)
        {
            auto WriteOperation =
                [TransmissionObject = Trans_, BufferSequence](auto &&Handler) mutable
                {
                    using HandlerType = std::decay_t<decltype(Handler)>;
                    auto State = std::make_shared<WriteState<HandlerType>>();
                    State->Trans = TransmissionObject;
                    for (auto It = Net::buffer_sequence_begin(BufferSequence),
                              End = Net::buffer_sequence_end(BufferSequence);
                         It != End; ++It)
                    {
                        State->Buffers.emplace_back(*It);
                    }
                    State->Completion.emplace(std::forward<decltype(Handler)>(Handler));
                    const auto HandlerExecutor = Net::get_associated_executor(*State->Completion,
                                                                                TransmissionObject->Executor());
                    auto WriteNextOperation = [State]() mutable { WriteNext(State); };
                    Net::post(HandlerExecutor, std::move(WriteNextOperation));
                };
            return Net::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(
                std::move(WriteOperation), CompletionTokenObject);
        }

        /**
         * @brief 完整写入操作
         * @details 委托给 Transmission 的 AsyncWrite 虚函数。
         * 允许子类（如 UDP）自定义完整写入行为。
         * @param Buffer 要写入的数据缓冲区
         * @param ec 错误码输出参数，成功时为默认值
         * @return net::awaitable<std::size_t> 协程对象，完成后返回实际写入的总字节数
         */
        [[nodiscard]] auto AsyncWrite(std::span<const std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>
        {
            co_return co_await Trans_->AsyncWrite(Buffer, ErrorCode);
        }

        /**
         * @brief 完整读取操作
         * @details 委托给 Transmission 的 AsyncRead 虚函数。
         * 允许子类自定义完整读取行为。
         * @param Buffer 接收数据的缓冲区
         * @param ec 错误码输出参数，成功时为默认值
         * @return net::awaitable<std::size_t> 协程对象，完成后返回实际读取的总字节数
         */
        [[nodiscard]] auto AsyncRead(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>
        {
            co_return co_await Trans_->AsyncRead(Buffer, ErrorCode);
        }

        using LowestLayerType = Connector;

        /**
         * @brief 获取底层对象
         * @details 返回 Connector 自身的引用，满足 Boost.Asio 的
         * lowest_layer 访问要求。
         * @return LowestLayerType& 当前对象的引用
         */
        [[nodiscard]] auto LowestLayer() -> LowestLayerType &
        {
            return *this;
        }

        /**
         * @brief 获取底层对象（常量版本）
         * @details 返回 Connector 自身的常量引用，满足 Boost.Asio 的
         * lowest_layer 常量访问要求。
         * @return const LowestLayerType& 当前对象的常量引用
         */
        [[nodiscard]] auto LowestLayer() const -> const LowestLayerType &
        {
            return *this;
        }

        /**
         * @brief 获取底层传输层对象
         * @details 返回内部持有的传输层对象的引用，用于直接操作传输层。
         * @return Transmission& 传输层对象的引用
         */
        [[nodiscard]] auto Transmission() const -> Transmission &
        {
            return *Trans_;
        }

        /**
         * @brief 释放传输层所有权
         * @details 将内部持有的传输层指针移动返回，调用后对象不再持有传输层。
         * @return TransmissionPtr 传输层对象指针
         */
        [[nodiscard]] auto Release() -> TransmissionPtr
        {
            return std::move(Trans_);
        }

    private:
        template <typename MutableBufferSequence>
        [[nodiscard]] static auto CollectMutableBuffers(const MutableBufferSequence &BufferSequence)
            -> std::vector<Net::mutable_buffer>
        {
            std::vector<Net::mutable_buffer> Result;
            for (auto It = Net::buffer_sequence_begin(BufferSequence),
                      End = Net::buffer_sequence_end(BufferSequence);
                 It != End; ++It)
            {
                Result.emplace_back(*It);
            }
            return Result;
        }

        [[nodiscard]] static auto CopyToBuffers(std::span<const std::byte> Source,
                                                const std::vector<Net::mutable_buffer> &Buffers) -> std::size_t
        {
            std::size_t Copied = 0;
            for (const auto Buffer : Buffers)
            {
                if (Copied >= Source.size())
                {
                    break;
                }
                const auto Count = std::min(Buffer.size(), Source.size() - Copied);
                if (Count > 0)
                {
                    std::memcpy(Buffer.data(), Source.data() + Copied, Count);
                    Copied += Count;
                }
            }
            return Copied;
        }

        template <typename Handler>
        static auto PostCompletion(const Net::any_io_executor &DefaultExecutor,
                                   Handler &&HandlerFn,
                                   boost::system::error_code Ec,
                                   const std::size_t N) -> void
        {
            const auto HandlerExecutor = Net::get_associated_executor(HandlerFn, DefaultExecutor);
            auto Callback = std::forward<Handler>(HandlerFn);
            auto CompletionOperation = [Callback = std::move(Callback), Ec = std::move(Ec), N]() mutable
            { std::move(Callback)(Ec, N); };
            Net::post(HandlerExecutor, std::move(CompletionOperation));
        }

        template <typename Handler>
        struct ReadState
        {
            TransmissionPtr Trans;
            std::vector<Net::mutable_buffer> Buffers;
            std::vector<std::byte> Scratch;
            std::size_t Capacity{0};
            bool UsesScratch{false};
            std::optional<Handler> Completion;
        };

        template <typename Handler>
        static auto CompleteRead(const std::shared_ptr<ReadState<Handler>> &State,
                                 boost::system::error_code Ec,
                                 std::size_t N) -> void
        {
            if (N > State->Capacity)
            {
                Ec = Preview::make_error_code(Preview::Error::BrokenPipe);
                N = 0;
            }
            if (State->UsesScratch && N > 0)
            {
                (void)CopyToBuffers(std::span<const std::byte>(State->Scratch).first(N), State->Buffers);
            }
            auto Completion = std::move(*State->Completion);
            State->Completion.reset();
            PostCompletion(State->Trans->Executor(), std::move(Completion), std::move(Ec), N);
        }

        template <typename Handler>
        struct WriteState
        {
            TransmissionPtr Trans;
            std::vector<Net::const_buffer> Buffers;
            std::size_t Index{0};
            std::size_t Offset{0};
            std::size_t Total{0};
            std::optional<Handler> Completion;
        };

        template <typename Handler>
        static auto WriteNext(const std::shared_ptr<WriteState<Handler>> &State) -> void
        {
            while (State->Index < State->Buffers.size() &&
                   State->Offset >= State->Buffers[State->Index].size())
            {
                ++State->Index;
                State->Offset = 0;
            }

            if (State->Index >= State->Buffers.size())
            {
                auto HandlerFn = std::move(*State->Completion);
                State->Completion.reset();
                PostCompletion(State->Trans->Executor(), std::move(HandlerFn), {}, State->Total);
                return;
            }

            const auto Buffer = State->Buffers[State->Index];
            const auto Remaining = Buffer.size() - State->Offset;
            const auto *Data = reinterpret_cast<const std::byte *>(Buffer.data()) + State->Offset;
            auto WriteCompletion =
                [State](boost::system::error_code Ec, const std::size_t Written) mutable
                {
                    const auto RemainingNow =
                        State->Buffers[State->Index].size() - State->Offset;
                    if (Written > RemainingNow)
                    {
                        auto HandlerFn = std::move(*State->Completion);
                        State->Completion.reset();
                        PostCompletion(State->Trans->Executor(), std::move(HandlerFn),
                                       Preview::make_error_code(Preview::Error::BrokenPipe), State->Total);
                        return;
                    }
                    if (Ec)
                    {
                        auto HandlerFn = std::move(*State->Completion);
                        State->Completion.reset();
                        PostCompletion(State->Trans->Executor(), std::move(HandlerFn), std::move(Ec),
                                       State->Total + Written);
                        return;
                    }
                    if (Written == 0)
                    {
                        auto HandlerFn = std::move(*State->Completion);
                        State->Completion.reset();
                        PostCompletion(State->Trans->Executor(), std::move(HandlerFn),
                                       Preview::make_error_code(Preview::Error::BrokenPipe), State->Total);
                        return;
                    }
                    State->Offset += Written;
                    State->Total += Written;
                    const auto HandlerExecutor = Net::get_associated_executor(*State->Completion,
                                                                                State->Trans->Executor());
                    auto WriteNextOperation = [State]() mutable { WriteNext(State); };
                    Net::post(HandlerExecutor, std::move(WriteNextOperation));
                };
            State->Trans->async_write_some(std::span<const std::byte>(Data, Remaining),
                                           std::move(WriteCompletion));
        }

        TransmissionPtr Trans_;                   // 传输层对象的共享指针
        std::vector<std::byte> PrereadBuffer_; // 预读数据缓冲区
        std::size_t PrereadOffset_ = 0;           // 预读数据当前消费偏移量
    }; // class Connector
} // namespace Preview::Transport
