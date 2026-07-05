/**
 * @file session_handle.hpp
 * @brief 会话只读视图
 * @details 替代 stealth_opts::context::session* 的反向穿透。仅暴露 stealth/protocol
 * 层白名单字段（conn_id/arena/buffer_size/detected/lease/worker_res），隐藏
 * worker_ctx/server_ctx 等内部，防止反向穿透到 instance::worker/server。
 *
 * 设计目的：
 *   - 限制 stealth 层只能访问必要字段，建立明确分层边界
 *   - 替代 stealth_opts::session* + frame_arena* 双字段（合并为单一视图）
 *   - 提供 worker_res() 让 stealth 层 lock worker::resources 安全借用
 *
 * @note 不拥有任何资源，仅持引用/指针，生命周期由调用方（context::session）保证
 */
#pragma once

#include <prism/account/entry.hpp>
#include <prism/worker/resources.hpp>
#include <prism/foundation/memory/pool.hpp>
#include <prism/proto/protocol/types.hpp>

#include <cstdint>


namespace psm::context
{
    /**
     * @class session_handle
     * @brief 会话只读视图
     * @details 限制 stealth/protocol 层只能访问白名单字段，防止反向穿透到
     * instance::worker/server 内部。worker_res 提供 weak_ptr 让 stealth 层
     * 安全借用 worker::resources（lock 后判空使用）。
     * @note 构造时传入 worker::borrow 引用，调用方需保证 worker::resources
     *       生命周期覆盖 session_handle 使用期间
     */
    class session_handle
    {
    public:
        /**
         * @brief 构造会话视图
         * @param conn_id 连接唯一标识符
         * @param arena 帧内存池引用
         * @param buffer_size 数据传输缓冲区大小
         * @param detected 已识别的协议类型
         * @param lease 账户租约指针（可空）
         * @param worker_res worker::resources 弱引用
         */
        session_handle(
            std::uint64_t conn_id,
            memory::frame_arena &arena,
            std::uint32_t buffer_size,
            protocol::protocol_type detected,
            account::lease *lease,
            worker::borrow worker_res) noexcept
            : conn_id_(conn_id),
              arena_(arena),
              buffer_size_(buffer_size),
              detected_(detected),
              lease_(lease),
              worker_res_(std::move(worker_res))
        {
        }

        [[nodiscard]] auto conn_id() const noexcept -> std::uint64_t { return conn_id_; }
        [[nodiscard]] auto arena() noexcept -> memory::frame_arena & { return arena_; }
        [[nodiscard]] auto buffer_size() const noexcept -> std::uint32_t { return buffer_size_; }
        [[nodiscard]] auto detected() const noexcept -> protocol::protocol_type { return detected_; }
        [[nodiscard]] auto lease() noexcept -> account::lease * { return lease_; }

        /**
         * @brief 获取 worker::resources 弱引用
         * @return worker::borrow 引用
         * @details 调用方需 lock() 后判空使用，nullptr 表示 worker 已析构。
         */
        [[nodiscard]] auto worker_res() const noexcept -> const worker::borrow &
        {
            return worker_res_;
        }

        /**
         * @brief 锁定 worker::resources
         * @return worker::handle（shared_ptr），nullptr 表示 worker 已析构
         */
        [[nodiscard]] auto lock_worker() const -> worker::handle
        {
            return worker_res_.lock();
        }

    private:
        std::uint64_t conn_id_;
        memory::frame_arena &arena_;
        std::uint32_t buffer_size_;
        protocol::protocol_type detected_;
        account::lease *lease_;
        worker::borrow worker_res_;
    };

} // namespace psm::context
