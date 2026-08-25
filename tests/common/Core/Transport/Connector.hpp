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

#include <common/Core/Memory/Container.hpp>
#include <common/Core/Transmission.hpp>

#include <boost/asio.hpp>

#include <span>
#include <utility>

namespace Preview::Transport {

    namespace net = boost::asio;

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
        using ExecutorType = net::any_io_executor;
        using executor_type = net::any_io_executor;
        using TransmissionPtr = Preview::SharedTransmission;
        using lowest_layer_type = Transmission;

        [[nodiscard]] auto lowest_layer() noexcept -> Transmission & { return *trans_; }
        [[nodiscard]] auto lowest_layer() const noexcept -> const Transmission & { return *trans_; }

        /**
         * @brief 构造函数（传输层指针 + 预读数据）
         * @details 使用传输层指针和可选的预读数据构造适配器。
         * 预读数据将在首次 AsyncReadSome 调用时优先返回，
         * 避免协议检测阶段已读取的数据丢失。
         * @param trans 传输层对象指针，所有权将被转移
         * @param preread 预读数据切片，默认为空
         */
        explicit Connector(TransmissionPtr trans, std::span<const std::byte> preread = {})
            : trans_(std::move(trans))
        {
            if (!preread.empty())
            {
                PrereadBuffer_.assign(preread.begin(), preread.end());
            }
        }

        /**
         * @brief 移动构造函数
         * @details 转移传输层指针、预读缓冲区和偏移量的所有权。
         * 移动后源对象的偏移量被重置为零。
         * @param other 要移动的适配器对象
         */
        Connector(Connector &&other) noexcept
            : trans_(std::move(other.trans_)), PrereadBuffer_(std::move(other.PrereadBuffer_)),
              PrereadOffset_(other.PrereadOffset_)
        {
            other.PrereadOffset_ = 0;
        }

        /**
         * @brief 移动赋值运算符
         * @details 转移传输层指针、预读缓冲区和偏移量的所有权。
         * 移动后源对象的偏移量被重置为零。防止自赋值。
         * @param other 要移动的适配器对象
         * @return Connector& 当前对象的引用
         */
        auto operator=(Connector &&other) noexcept -> Connector &
        {
            if (this != &other)
            {
                trans_ = std::move(other.trans_);
                PrereadBuffer_ = std::move(other.PrereadBuffer_);
                PrereadOffset_ = other.PrereadOffset_;
                other.PrereadOffset_ = 0;
            }
            return *this;
        }

        /**
         * @brief 获取执行器
         * @details 返回底层传输层关联的执行器，满足 Boost.Asio 的
         * AsyncStream 概念要求。
         * @return ExecutorType 执行器对象
         */
        [[nodiscard]] auto GetExecutor() -> ExecutorType
        {
            return trans_->Executor();
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         * @return 底层 Transmission 指针
         */
        [[nodiscard]] auto NextLayer() noexcept -> Transmission *
        {
            return trans_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 底层 Transmission 指针
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission *
        {
            return trans_.get();
        }

        /**
         * @brief 获取执行器
         * @details 委托给 GetExecutor()，提供便捷的执行器访问。
         * @return ExecutorType 执行器对象
         */
        [[nodiscard]] auto Executor() -> ExecutorType
        {
            return GetExecutor();
        }

        /// @brief Asio 概念兼容层（规范 v2 例外）：Boost.Asio 以精确小写名
        ///        调用下一层（ssl::stream 等），以下三个转发不可改名。
        auto get_executor() -> ExecutorType { return GetExecutor(); }

        template <typename... Args>
        auto async_read_some(Args &&...args)
        {
            return AsyncReadSome(std::forward<Args>(args)...);
        }

        template <typename... Args>
        auto async_write_some(Args &&...args)
        {
            return AsyncWriteSome(std::forward<Args>(args)...);
        }

        /**
         * @brief 适配 AsyncReadSome
         * @details 将 Boost.Asio 的 AsyncReadSome 调用适配到 Transmission 接口。
         * 如果存在未消费的预读数据，优先从预读缓冲区拷贝到用户缓冲区，
         * 避免额外的异步读取操作。预读数据消费完毕后委托给传输层。
         * @tparam MutableBufferSequence 可变缓冲区序列类型
         * @tparam CompletionToken 完成令牌类型（协程、回调等）
         * @param buffers 可变缓冲区序列，用于存储读取的数据
         * @param token 完成令牌，用于接收读取结果
         * @return 异步操作结果，类型取决于完成令牌
         */
        template <typename MutableBufferSequence, typename CompletionToken>
        [[maybe_unused]] auto AsyncReadSome(const MutableBufferSequence &buffers, CompletionToken &&token)
        {
            if (PrereadOffset_ < PrereadBuffer_.size())
            {
                std::size_t BytesAvailable = PrereadBuffer_.size() - PrereadOffset_;
                std::size_t BytesToCopy = 0;
                auto BufIt = net::buffer_sequence_begin(buffers);
                auto BufEnd = net::buffer_sequence_end(buffers);
                for (; BufIt != BufEnd && BytesToCopy < BytesAvailable; ++BufIt)
                {
                    auto buf = *BufIt;
                    std::size_t BufSize = buf.size();
                    std::size_t CopySize = std::min(BufSize, BytesAvailable - BytesToCopy);
                    std::memcpy(buf.data(), PrereadBuffer_.data() + PrereadOffset_ + BytesToCopy,
                                CopySize);
                    BytesToCopy += CopySize;
                }
                PrereadOffset_ += BytesToCopy;
                auto handler = [BytesToCopy]<typename Callback>(Callback &&handler)
                {
                    boost::system::error_code ec;
                    std::forward<Callback>(handler)(ec, BytesToCopy);
                };
                return net::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(
                    handler, token);
            }

            // 预读数据已耗尽，直接委托给传输层的 completion-handler 方法
            // 读语义：填充首个非空缓冲（ReadSome 语义允许；非连续缓冲无法单次填充）
            return net::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(
                [trans = trans_, first_buf = *net::buffer_sequence_begin(buffers)](auto &&handler) mutable
                {
                    // asio mutable_buffer::Data() 返回 void*，byte_span helper 不覆盖，
                    // 保留显式转换
                    std::span<std::byte> span(reinterpret_cast<std::byte *>(first_buf.data()),
                                              first_buf.size());
                    trans->AsyncReadSome(span, std::forward<decltype(handler)>(handler));
                },
                token);
        }

        /**
         * @brief 适配 AsyncWriteSome
         * @details 将 Boost.Asio 的 AsyncWriteSome 调用直接委托给传输层。
         * @tparam ConstBufferSequence 常量缓冲区序列类型
         * @tparam CompletionToken 完成令牌类型
         * @param buffers 常量缓冲区序列，包含要写入的数据
         * @param token 完成令牌，用于接收写入结果
         * @return 异步操作结果，类型取决于完成令牌
         */
        template <typename ConstBufferSequence, typename CompletionToken>
        auto AsyncWriteSome(const ConstBufferSequence &buffers, CompletionToken &&token)
        {
            return net::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(
                [trans = trans_, buffers](auto &&handler) mutable
                {
                    // 遍历全部缓冲逐段写入（不静默丢弃后续缓冲）
                    auto it = net::buffer_sequence_begin(buffers);
                    const auto end = net::buffer_sequence_end(buffers);
                    auto h = std::make_shared<std::decay_t<decltype(handler)>>(
                        std::forward<decltype(handler)>(handler));
                    auto next = [trans, end, h](auto &&self, auto it, std::size_t Done) mutable -> void
                    {
                        if (it == end)
                        {
                            boost::system::error_code ec;
                            (*h)(ec, Done);
                            return;
                        }
                        auto buf = *it;
                        std::span<const std::byte> span(reinterpret_cast<const std::byte *>(buf.data()),
                                                        buf.size());
                        trans->AsyncWriteSome(span,
                                                [self, it, end, h, Done](boost::system::error_code ec,
                                                                         std::size_t n) mutable
                                                {
                                                    if (ec)
                                                    {
                                                        (*h)(ec, Done + n);
                                                        return;
                                                    }
                                                    self(self, ++it, Done + n);
                                                });
                    };
                    next(next, it, 0);
                },
                token);
        }

        /**
         * @brief 完整写入操作
         * @details 委托给 Transmission 的 AsyncWrite 虚函数。
         * 允许子类（如 UDP）自定义完整写入行为。
         * @param Buffer 要写入的数据缓冲区
         * @param ec 错误码输出参数，成功时为默认值
         * @return net::awaitable<std::size_t> 协程对象，完成后返回实际写入的总字节数
         */
        [[nodiscard]] auto AsyncWrite(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            co_return co_await trans_->AsyncWrite(Buffer, ec);
        }

        /**
         * @brief 完整读取操作
         * @details 委托给 Transmission 的 AsyncRead 虚函数。
         * 允许子类自定义完整读取行为。
         * @param Buffer 接收数据的缓冲区
         * @param ec 错误码输出参数，成功时为默认值
         * @return net::awaitable<std::size_t> 协程对象，完成后返回实际读取的总字节数
         */
        [[nodiscard]] auto AsyncRead(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            co_return co_await trans_->AsyncRead(Buffer, ec);
        }

        using LowestLayerType = Connector;

        /**
         * @brief 获取底层对象
         * @details 返回 Connector 自身的引用，满足 Boost.Asio 的
         * LowestLayer 访问要求。
         * @return LowestLayerType& 当前对象的引用
         */
        [[nodiscard]] auto LowestLayer() -> LowestLayerType &
        {
            return *this;
        }

        /**
         * @brief 获取底层对象（常量版本）
         * @details 返回 Connector 自身的常量引用，满足 Boost.Asio 的
         * LowestLayer 常量访问要求。
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
            return *trans_;
        }

        /**
         * @brief 释放传输层所有权
         * @details 将内部持有的传输层指针移动返回，调用后对象不再持有传输层。
         * @return TransmissionPtr 传输层对象指针
         */
        [[nodiscard]] auto Release() -> TransmissionPtr
        {
            return std::move(trans_);
        }

    private:
        TransmissionPtr trans_;                   // 传输层对象的共享指针
        std::vector<std::byte> PrereadBuffer_; // 预读数据缓冲区
        std::size_t PrereadOffset_ = 0;           // 预读数据当前消费偏移量
    }; // class Connector
} // namespace Preview::Transport
