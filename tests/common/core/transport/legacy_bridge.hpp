/**
 * @file legacy_bridge.hpp
 * @brief 旧接口桥接器（transmission → transport_base）
 * @details 测试库迁移期工具：新接口的 shared_transmission 包装为旧
 * transport_base 接口，供仍使用旧接口的组件（如 mux session 引擎、
 * 旧协议 client/server）消费，实现新旧传输模型的平滑共存。
 * @note transmission 接口无半关与超时概念：shutdown/set_timeout 为空操作。
 * @note 桥接器生命周期与消费方绑定，close() 时同步关闭底层传输。
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/core/transport/transport_base.hpp>

namespace psmtest
{

    /**
     * @class legacy_bridge
     * @brief 旧接口桥接器（transmission → transport_base）
     * @details 包装新接口的 shared_transmission，实现旧 transport_base
     * 的 read_some/write_all/shutdown/close/cancel/set_timeout/is_open/
     * executor 虚接口。close() 为协程形式（transport_base 约定），内部
     * 直接调用 transmission 的同步 close()，随后 co_return。
     */
    class legacy_bridge : public transport_base
    {
    public:
        /**
         * @brief 构造
         * @param raw 新接口底层传输（所有权移交）
         */
        explicit legacy_bridge(shared_transmission raw) : raw_(std::move(raw))
        {
        }

        /**
         * @brief 读取最多 buf.size() 字节
         * @param buf 接收缓冲区
         * @return 实际读取字节数；0 = EOF / 错误（错误不区分，符合旧接口语义）
         */
        auto read_some(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t> override
        {
            if (!raw_)
            {
                co_return 0;
            }
            std::error_code ec;
            const auto n = co_await raw_->async_read_some(
                std::span<std::byte>(reinterpret_cast<std::byte *>(buf.data()), buf.size()), ec);
            if (ec)
            {
                co_return 0;
            }
            co_return n;
        }

        /**
         * @brief 写入全部 buf 字节
         * @param buf 待写数据
         * @return 错误码（成功 = 空）；底层错误经 to_ec 映射为协议错误
         */
        auto write_all(std::span<const std::uint8_t> buf) -> net::awaitable<protocol_ec> override
        {
            if (!raw_)
            {
                co_return make_error_code(error::broken_pipe);
            }
            std::size_t done = 0;
            while (done < buf.size())
            {
                std::error_code ec;
                const auto n = co_await raw_->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(buf.data() + done),
                                               buf.size() - done),
                    ec);
                if (ec)
                {
                    co_return detail::to_ec(ec);
                }
                if (n == 0)
                {
                    co_return make_error_code(error::broken_pipe);
                }
                done += n;
            }
            co_return boost::system::error_code{};
        }

        /**
         * @brief 优雅半关
         * @details transmission 接口无半关概念，空操作（尽力而为）。
         */
        auto shutdown() -> net::awaitable<void> override
        {
            co_return;
        }

        /**
         * @brief 立即关闭
         * @details 同步调用 transmission::close() 关闭底层连接，随后直接返回。
         */
        auto close() -> net::awaitable<void> override
        {
            closed_ = true;
            if (raw_)
            {
                raw_->close();
            }
            co_return;
        }

        /**
         * @brief 取消挂起操作
         */
        auto cancel() -> void override
        {
            if (raw_)
            {
                raw_->cancel();
            }
        }

        /**
         * @brief 设置读超时
         * @param ms 超时毫秒数（忽略）
         * @details transmission 接口无超时概念，空操作。
         */
        auto set_timeout(std::chrono::milliseconds /*ms*/) -> void override
        {
        }

        /**
         * @brief 流是否打开（未主动关闭）
         * @return 打开返回 true
         */
        [[nodiscard]] auto is_open() const -> bool override
        {
            return !closed_ && raw_ != nullptr;
        }

        /**
         * @brief 获取执行器
         * @return 关联的执行器
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return raw_ ? raw_->executor() : net::any_io_executor{};
        }

    private:
        shared_transmission raw_; ///< 新接口底层传输（共享所有权）
        bool closed_{false};      ///< 关闭标志（is_open 依据）
    };

    /// 旧接口桥接器共享指针
    using shared_bridge = std::shared_ptr<legacy_bridge>;

    /**
     * @brief 创建旧接口桥接器
     * @param raw 新接口底层传输
     * @return 桥接器共享指针
     * @details 工厂函数，供旧接口组件快速包装新传输。
     */
    [[nodiscard]] inline auto make_legacy(shared_transmission raw) -> shared_bridge
    {
        return std::make_shared<legacy_bridge>(std::move(raw));
    }

} // namespace psmtest
