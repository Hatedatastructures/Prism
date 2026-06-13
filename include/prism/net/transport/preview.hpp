/**
 * @file preview.hpp
 * @brief 预读数据回放包装器
 * @details 在协议嗅探阶段，部分数据可能已被从入站传输中读取。
 * 该包装器将这些预读数据保存在内部，在后续读取时优先返回预读
 * 数据，待预读数据耗尽后再委托给内部传输对象。这确保了协议
 * 管道在嗅探后仍能一致地处理数据流。
 * @note 该类继承自 transmission 抽象基类，可透明地替换原始传输。
 * @note 预读数据在构造时被复制到内部缓冲区，确保数据生命周期安全。
 */

#pragma once

#include <prism/core/memory/container.hpp>
#include <prism/core/memory/pool.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>
#include <boost/asio/any_completion_handler.hpp>

#include <cstddef>
#include <memory>
#include <span>
#include <system_error>


namespace psm::transport
{

    namespace net = boost::asio;

    /**
     * @class preview
     * @brief 预读数据回放包装器
     * @details 继承 transmission 抽象基类，在内部传输层外包装一层
     * 预读数据。优先从内部缓冲区返回数据，耗完后委托给内部传输。
     */
    class preview final : public transmission
    {
    public:
        /**
         * @brief 构造预读回放包装器
         * @param inner 被包装的内部传输对象
         * @param preread 协议嗅探期间捕获的预读数据
         * @param mr 内存资源，用于预读缓冲区分配
         * @details 构造时会将预读数据复制到内部缓冲区，确保数据所有权安全。
         */
        explicit preview(shared_transmission inner, std::span<const std::byte> preread,
                         memory::resource_pointer mr = memory::current_resource());

        /**
         * @brief 获取内层传输
         * @details 装饰器链导航，返回被包装的内层传输指针。
         * @return transmission* 内层传输指针
         */
        [[nodiscard]] auto next_layer() noexcept -> transmission * override
        {
            return inner_.get();
        }

        [[nodiscard]] auto next_layer() const noexcept -> const transmission * override
        {
            return inner_.get();
        }

        /**
         * @brief 报告内部传输是否可靠
         * @return 若内部传输可靠则返回 true，否则返回 false
         */
        [[nodiscard]] auto transport_type() const noexcept
            -> type override
        {
            if (inner_)
                return inner_->transport_type();
            return type::tcp;
        }

        /**
         * @brief 获取内部传输的执行器
         * @details 委托给内部传输对象的 executor 方法
         * @return executor_type 绑定到内部传输的执行器
         */
        [[nodiscard]] auto executor() const -> executor_type override;

        /**
         * @brief 从预读缓冲区或内部流读取数据
         * @param buffer 目标缓冲区
         * @param ec 输出错误码
         * @return 协程对象，完成后返回读取的字节数
         * @details 优先从预读缓冲区返回数据，预读数据耗尽后委托给
         * 内部传输对象进行实际读取。
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief 异步写入数据
         * @param buffer 源数据缓冲区
         * @param ec 输出错误码
         * @return 协程对象，完成后返回写入的字节数
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        /**
         * @brief Completion-handler 风格异步读取
         * @details 预读数据同步完成，耗尽后委托给内部传输。
         * @param buffer 目标缓冲区
         * @param handler 完成处理器
         */
        void async_read_some(std::span<std::byte> buffer, net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler) override;

        /**
         * @brief Completion-handler 风格异步写入
         * @details 委托给内部传输的 completion-handler 方法。
         * @param buffer 源数据缓冲区
         * @param handler 完成处理器
         */
        void async_write_some(std::span<const std::byte> buffer, net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler) override;

        /**
         * @brief 完整写入操作
         * @details 委托给内部传输的 async_write 自由函数。
         */
        [[nodiscard]] auto async_write(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            if (!inner_)
            {
                ec = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            co_return co_await transport::async_write(*inner_, buffer, ec);
        }

        /**
         * @brief 关闭内部传输流
         * @details 清空预读缓冲区后关闭内部传输连接
         */
        void close() override;

        /**
         * @brief 取消内部传输的待处理操作
         * @details 取消内部传输对象上所有挂起的异步读写操作
         */
        void cancel() override;

        /**
         * @brief 获取内部传输对象
         * @return 内部传输的 shared_ptr
         */
        [[nodiscard]] auto inner() const noexcept
            -> shared_transmission { return inner_; }

    private:
        shared_transmission inner_;                // 内部传输对象
        memory::vector<std::byte> preread_buffer_; // 预读数据缓冲区（拥有所有权）
        std::size_t offset_{0};                    // 当前预读偏移量
    };

    /**
     * @brief 将入站传输包装为带预读数据的传输
     * @param inbound 入站传输（所有权转移）
     * @param data 协议嗅探期间捕获的预读数据
     * @param mr 内存资源，用于预读缓冲区分配
     * @return 包装后的传输对象；若 data 为空则直接返回原始入站传输
     * @details 若 data 不为空，将 inbound 的所有权转移到 preview 包装器中，
     * 在后续读取时优先重放预读数据。
     * @note 调用后入站传输所有权转移至返回值。
     */
    [[nodiscard]] inline auto wrap_with_preview(shared_transmission inbound, std::span<const std::byte> data, memory::resource_pointer mr = memory::current_resource())
        -> shared_transmission
    {
        if (!data.empty())
        {
            inbound = std::make_shared<preview>(std::move(inbound), data, mr);
        }
        return inbound;
    }

} // namespace psm::transport
