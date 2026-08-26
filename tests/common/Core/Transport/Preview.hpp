/**
 * @file Preview.hpp
 * @brief 预读数据回放包装器
 * @details 在协议嗅探阶段，部分数据可能已被从入站传输中读取。
 * 该包装器将这些预读数据保存在内部，在后续读取时优先返回预读
 * 数据，待预读数据耗尽后再委托给内部传输对象。这确保了协议
 * 管道在嗅探后仍能一致地处理数据流。
 * @note 该类继承自 Transmission 抽象基类，可透明地替换原始传输。
 * @note 预读数据在构造时被复制到内部缓冲区，确保数据生命周期安全。
 */

#pragma once

#include <common/Core/Diagnose/Log.hpp>

#include <common/Core/Memory/Container.hpp>
#include <common/Core/Memory/Pool.hpp>
#include <common/Core/Transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/any_completion_handler.hpp>

#include <cstddef>
#include <memory>
#include <span>
#include <system_error>

namespace Preview::Transport {


    namespace net = boost::asio;

    /**
      * @class PreviewTransport
     * @brief 预读数据回放包装器
     * @details 继承 Transmission 抽象基类，在内部传输层外包装一层
     * 预读数据。优先从内部缓冲区返回数据，耗完后委托给内部传输。
     * @note PrereadBuffer_ 强制使用 GlobalPool（永生 PMR pool），不接受外部
     * Allocator。原因：Preview 可能被 detached 协程（multiplex::core）持有，
     * 生命周期脱离 Session；若用 Session.FrameArena 作为 Allocator，Session
     * 析构后 FrameArena 失效，Preview 析构时 m_resource 悬垂。详见
     * docs/ARCHITECTURE.md "资源所有权模型"。
     */
    class PreviewTransport final : public Transmission
    {
    public:
        /**
         * @brief 构造预读回放包装器
         * @param Inner 被包装的内部传输对象
         * @param preread 协议嗅探期间捕获的预读数据
         * @details 构造时会将预读数据复制到内部缓冲区。PrereadBuffer_ 使用
         * GlobalPool 分配（永生），保证 Preview 即使被 detached 协程长期持有，
         * 析构时也不会因 m_resource 悬垂崩溃。
         */
        explicit PreviewTransport(SharedTransmission Inner, std::span<const std::byte> preread);

        /**
         * @brief 获取内层传输
         * @details 装饰器链导航，返回被包装的内层传输指针。
         * @return Transmission* 内层传输指针
         */
        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
        {
            return Inner_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return const Transmission* 内层传输指针
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
        {
            return Inner_.get();
        }

        /**
         * @brief 报告内部传输是否可靠
         * @return 若内部传输可靠则返回 true，否则返回 false
         */
        [[nodiscard]] auto TransportType() const noexcept -> Type override
        {
            if (Inner_)
            {
                return Inner_->TransportType();
            }
            return Type::Tcp;
        }

        /**
         * @brief 获取内部传输的执行器
         * @details 委托给内部传输对象的 Executor 方法
         * @return ExecutorType 绑定到内部传输的执行器
         */
        [[nodiscard]] auto Executor() const -> ExecutorType override;

        /**
         * @brief 从预读缓冲区或内部流读取数据
         * @param Buffer 目标缓冲区
         * @param ec 输出错误码
         * @return 协程对象，完成后返回读取的字节数
         * @details 优先从预读缓冲区返回数据，预读数据耗尽后委托给
         * 内部传输对象进行实际读取。
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @param Buffer 源数据缓冲区
         * @param ec 输出错误码
         * @return 协程对象，完成后返回写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief Completion-handler 风格异步读取
         * @details 预读数据同步完成，耗尽后委托给内部传输。
         * @param Buffer 目标缓冲区
         * @param handler 完成处理器
         */
        void async_read_some(
            std::span<std::byte> Buffer,
            net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler) override;

        /**
         * @brief Completion-handler 风格异步写入
         * @details 委托给内部传输的 completion-handler 方法。
         * @param Buffer 源数据缓冲区
         * @param handler 完成处理器
         */
        void async_write_some(
            std::span<const std::byte> Buffer,
            net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler) override;

        /**
         * @brief 完整写入操作
         * @details 委托给内部传输的 AsyncWrite 自由函数。
         */
        [[nodiscard]] auto AsyncWrite(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            if (!Inner_)
            {
                ec = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            co_return co_await Inner_->AsyncWrite(Buffer, ec);
        }

        /**
         * @brief 关闭内部传输流
         * @details 清空预读缓冲区后关闭内部传输连接
         */
        void Close() override;

        /**
         * @brief 取消内部传输的待处理操作
         * @details 取消内部传输对象上所有挂起的异步读写操作
         */
        void Cancel() override;

        /**
         * @brief 获取内部传输对象
         * @return 内部传输的 shared_ptr
         */
        [[nodiscard]] auto Inner() const noexcept -> SharedTransmission
        {
            return Inner_;
        }

    private:
        SharedTransmission Inner_;                // 内部传输对象
        std::vector<std::byte> PrereadBuffer_; // 预读数据缓冲区（拥有所有权）
        std::size_t Offset_{0};                    // 当前预读偏移量
    };

    /**
     * @brief 将入站传输包装为带预读数据的传输
     * @param Inbound 入站传输（所有权转移）
     * @param Data 协议嗅探期间捕获的预读数据
     * @return 包装后的传输对象；若 Data 为空则直接返回原始入站传输
     * @details 若 Data 不为空，将 Inbound 的所有权转移到 Preview 包装器中，
     * 在后续读取时优先重放预读数据。Preview 内部 PrereadBuffer_ 用 GlobalPool
     * 分配（永生），不接受外部 PMR Allocator，避免 Session 级资源外流到 detached
     * 协程（详见 docs/ARCHITECTURE.md）。
     * @note 调用后入站传输所有权转移至返回值。
     */
    [[nodiscard]] inline auto WrapWithPreview(SharedTransmission Inbound, std::span<const std::byte> Data)
        -> SharedTransmission
    {
        if (!Data.empty())
        {
            Inbound = std::make_shared<PreviewTransport>(std::move(Inbound), Data);
        }
        return Inbound;
    }




    inline PreviewTransport::PreviewTransport(SharedTransmission Inner, std::span<const std::byte> preread)
        : Inner_(std::move(Inner)), PrereadBuffer_(preread.begin(), preread.end())
    {
    }

    inline auto PreviewTransport::Executor() const -> ExecutorType
    {
        if (!Inner_)
        {
            Diagnose::Error("Preview::Executor() called with null Inner transport");
            return ExecutorType{};
        }
        return Inner_->Executor();
    }

    inline auto PreviewTransport::async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (Offset_ < PrereadBuffer_.size())
        {
            const auto Remaining = PrereadBuffer_.size() - Offset_;
            const auto ToCopy = (std::min)(Remaining, Buffer.size());
            if (ToCopy > 0)
            {
                std::memcpy(Buffer.data(), PrereadBuffer_.data() + Offset_, ToCopy);
                Offset_ += ToCopy;
            }
            ec.clear();
            co_return ToCopy;
        }

        if (!Inner_)
        {
            ec = std::make_error_code(std::errc::bad_file_descriptor);
            co_return 0;
        }

        co_return co_await Inner_->async_read_some(Buffer, ec);
    }

    inline auto PreviewTransport::async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        if (!Inner_)
        {
            ec = std::make_error_code(std::errc::bad_file_descriptor);
            co_return 0;
        }
        co_return co_await Inner_->async_write_some(Buffer, ec);
    }

    inline void PreviewTransport::Close()
    {
        if (Inner_)
        {
            Inner_->Close();
        }
    }

    inline void PreviewTransport::Cancel()
    {
        if (Inner_)
        {
            Inner_->Cancel();
        }
    }

    inline void PreviewTransport::async_read_some(
        std::span<std::byte> Buffer,
        net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
    {
        if (Offset_ < PrereadBuffer_.size())
        {
            const auto Remaining = PrereadBuffer_.size() - Offset_;
            const auto ToCopy = (std::min)(Remaining, Buffer.size());
            if (ToCopy > 0)
            {
                std::memcpy(Buffer.data(), PrereadBuffer_.data() + Offset_, ToCopy);
                Offset_ += ToCopy;
            }
            std::move(handler)(boost::system::error_code{}, ToCopy);
            return;
        }

        if (!Inner_)
        {
            std::move(handler)(boost::system::error_code(static_cast<int>(std::errc::bad_file_descriptor),
                                                         boost::system::generic_category()),
                               0);
            return;
        }

        Inner_->async_read_some(Buffer, std::move(handler));
    }

    inline void PreviewTransport::async_write_some(
        std::span<const std::byte> Buffer,
        net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
    {
        if (!Inner_)
        {
            std::move(handler)(boost::system::error_code(static_cast<int>(std::errc::bad_file_descriptor),
                                                         boost::system::generic_category()),
                               0);
            return;
        }

        Inner_->async_write_some(Buffer, std::move(handler));
    }


} // namespace Preview::Transport
