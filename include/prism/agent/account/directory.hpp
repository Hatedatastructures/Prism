/**
 * @file directory.hpp
 * @brief 账户目录管理
 * @details 提供基于凭证的账户条目存储和查询能力，使用写时复制策略
 * 实现无锁读取。支持透明查找，允许直接使用 string_view 作为查询键，
 * 避免临时字符串构造开销。
 */

#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <prism/agent/account/entry.hpp>
#include <prism/memory/container.hpp>
#include <prism/memory/pool.hpp>

namespace psm::agent::account
{
    /**
     * @class directory
     * @brief 账户目录
     * @details 管理凭证到账户条目的映射关系，采用原子共享指针实现
     * 无锁读取和写时复制更新。所有修改操作都会复制整个映射表，
     * 适用于读多写少的账户配置场景。内部使用自定义内存池分配器，
     * 支持与内存池资源绑定。
     */
    class directory
    {
    public:
        /**
         * @struct transparent_hash
         * @brief 透明哈希函数
         * @details 支持 string_view 和 memory::string 的透明哈希计算，
         * 允许在查找时直接使用 string_view 避免临时对象构造。
         */
        struct transparent_hash
        { // 异构查找，减少临时对象构造开销
            using is_transparent = void;

            [[nodiscard]] auto operator()(const std::string_view value) const noexcept -> std::size_t
            {
                return std::hash<std::string_view>{}(value);
            }

            [[nodiscard]] auto operator()(const memory::string &value) const noexcept -> std::size_t
            {
                return std::hash<std::string_view>{}(std::string_view(value));
            }
        };

        /**
         * @struct transparent_equal
         * @brief 透明相等比较器
         * @details 支持 string_view 和 memory::string 的混合比较，
         * 配合透明哈希实现无临时对象的键查找。
         */
        struct transparent_equal
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(const memory::string &left, std::string_view right) const noexcept -> bool
            {
                return std::string_view(left) == right;
            }

            [[nodiscard]] auto operator()(const memory::string &left, const memory::string &right) const noexcept -> bool
            {
                return left == right;
            }

            [[nodiscard]] auto operator()(std::string_view left, const memory::string &right) const noexcept -> bool
            {
                return left == std::string_view(right);
            }
        };

        /**
         * @brief 构造账户目录
         * @param resource 内存池资源指针，默认使用全局内存池
         */
        explicit directory(memory::resource_pointer resource = memory::system::global_pool());

        /**
         * @brief 预留账户条目容量
         * @param n 预留的条目数量
         * @note 会触发写时复制，适用于批量插入前预分配
         */
        void reserve(std::size_t n);

        /**
         * @brief 清空所有账户条目
         * @details 原子替换为空映射表，原有条目在所有读取者释放后销毁
         */
        void clear();

        /**
         * @brief 插入或更新账户条目
         * @param credential 账户凭证字符串
         * @param max_connections 最大连接数限制，0 表示无限制
         * @details 若凭证不存在则创建新条目，存在则更新连接限制。
         * 操作会触发写时复制。
         */
        void upsert(std::string_view credential, std::uint32_t max_connections = 0);

        /**
         * @brief 插入已有条目到指定凭证键下
         * @param credential 账户凭证字符串
         * @param existing_entry 已有的账户条目共享指针
         * @details 将已有 entry 以新的凭证键注册到目录中，实现多协议凭证
         *（如 SHA224 哈希和 UUID）共享同一个 entry，从而共享连接数配额。
         * 操作会触发写时复制。
         * @note 调用方需确保 existing_entry 非 nullptr
         */
        void insert(std::string_view credential, std::shared_ptr<entry> existing_entry);

        /**
         * @brief 查找账户条目
         * @param credential 账户凭证字符串
         * @return 账户条目共享指针，未找到返回 nullptr
         * @note 无锁读取，返回的指针可安全跨线程使用
         */
        [[nodiscard]] auto find(std::string_view credential) const noexcept -> std::shared_ptr<entry>;

    private:
        using unordered_map = memory::unordered_map<memory::string, std::shared_ptr<entry>, transparent_hash, transparent_equal>;

        /**
         * @brief 写时复制更新映射表
         * @tparam UpdateFn 更新函数类型
         * @param update_fn 对副本执行的更新操作
         * @details 复制当前映射表，应用更新后通过 CAS 原子替换。
         * 若 CAS 失败则重试直到成功。
         */
        template <typename UpdateFn>
        void update_entries(UpdateFn &&update_fn)
        {
            auto current = entries_ptr_.load(std::memory_order_acquire);
            if (!current)
            { // 如果当前映射表为空，创建新映射表
                current = std::allocate_shared<unordered_map>(allocator_, 0);
            }

            while (true)
            { // 复制当前映射表，创建一个副本
                auto next = std::allocate_shared<unordered_map>(allocator_, *current);
                update_fn(*next); // 对副本执行更新操作
                if (entries_ptr_.compare_exchange_strong(current, next, std::memory_order_release, std::memory_order_acquire))
                { // 只有当 current 未被其他线程修改时才替换成功
                    return;
                }
                // 被其他线程抢先修改了，重试
            }
        }

        memory::allocator<std::byte> allocator_;                  // 自定义内存分配器
        std::atomic<std::shared_ptr<unordered_map>> entries_ptr_; // 原子共享指针，指向当前映射表
    };

    /**
     * @brief 尝试获取账户连接租约
     * @param accounts 账户目录
     * @param credential 账户凭证字符串
     * @return 成功返回持有租约的 lease 对象，失败返回空租约
     * @details 若账户不存在或已达到连接上限则返回空租约。
     * max_connections 为 0 表示无连接限制。成功时自动递增活跃连接数。
     */
    [[nodiscard]] inline auto try_acquire(const directory &accounts, const std::string_view credential) noexcept -> lease
    { // 无锁读取，返回的指针可安全跨线程使用
        auto entry_ptr = accounts.find(credential);
        if (!entry_ptr)
        { // 如果未找到，返回空租约
            return {};
        }

        if (entry_ptr->max_connections == 0)
        { // 如果无连接限制，直接递增活跃连接数
            entry_ptr->active_connections.fetch_add(1, std::memory_order_relaxed);
            return lease(std::move(entry_ptr)); // 返回持有租约的 lease 对象
        }
        // 如果有连接限制，尝试递增活跃连接数
        auto current = entry_ptr->active_connections.load(std::memory_order_relaxed);
        while (true)
        {
            if (current >= entry_ptr->max_connections)
            { // 如果已达到连接上限，返回空租约
                return {};
            }

            if (entry_ptr->active_connections.compare_exchange_weak(
                    current, current + 1, std::memory_order_relaxed, std::memory_order_relaxed))
            {                                       
                // active_connections 值和 current 相等，尝试递增活跃连接数
                return lease(std::move(entry_ptr)); // 返回持有租约的 lease 对象
            }
            // 不相等，说明其他线程已经修改了 active_connections，这个current是引用会自动更新到最新的值
        }
    }

    /**
     * @brief 检查账户是否存在
     * @param accounts 账户目录
     * @param credential 账户凭证字符串
     * @return 存在返回 true
     */
    [[nodiscard]] inline auto contains(const directory &accounts, const std::string_view credential) noexcept -> bool
    {
        return static_cast<bool>(accounts.find(credential));
    }
} // namespace psm::agent::account
