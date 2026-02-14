/**
 * @file validator.hpp
 * @brief 账户验证与连接数配额控制器
 * @details 提供基于凭据的用户认证和并发连接数限制功能，支持流量统计。
 * 该模块是代理服务的安全组件，用于防止资源滥用和实现用户级配额控制。
 *
 * 核心功能：
 * - 凭据验证：快速校验用户凭据是否存在；
 * - 连接配额：基于用户维度的并发连接数上限控制；
 * - 流量统计：用户维度的上下行流量字节数统计；
 * - 线程安全：无锁读取路径，适合高并发场景。
 *
 * 设计特性：
 * - Copy-on-Write：用户表更新采用写时复制，避免读路径阻塞；
 * - 原子计数：流量统计使用原子操作，无需锁同步；
 * - RAII 守卫：连接配额通过 `protector` 自动管理生命周期。
 *
 * ```
 * // 典型用法：启动阶段注入用户凭据，并在握手后申请配额
 * ngx::agent::validator validator;
 * validator.upsert_user("CREDENTIAL_1", 32);
 *
 * // 握手解析出凭据后：
 * auto guard = validator.try_acquire(credential);
 * if (!guard)
 * {
 *     // 超过并发上限或用户不存在
 *     co_return;
 * }
 *
 * // 在转发路径上做流量统计
 * ngx::agent::validator::accumulate_uplink(guard.state(), bytes);
 * ```
 *
 * @note `try_acquire` 返回 `protector`，其析构会自动释放一次连接配额。
 * @warning `upsert_user` 会按需分配内存，请在启动阶段完成用户表构建。
 */
#pragma once

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include <forward-engine/memory/container.hpp>
#include <forward-engine/memory/pool.hpp>

namespace ngx::agent
{
    /**
     * @class validator
     * @brief 账户验证与连接数配额控制器
     * @note `try_acquire` 返回 `protector`，其析构会自动释放一次连接配额，必须让其生命周期覆盖“连接存活期”。
     * @warning `upsert_user` 会按需分配内存并可能触发 `std::bad_alloc`；请在启动阶段完成用户表构建，避免在热路径频繁更新。
     * @details 该类用于在多种协议（如 `Trojan`, `HTTP`, `SOCKS5` 等）中实现：
     * @details - 基于 `credential` 的快速存在性校验（是否允许接入）；
     * @details - 基于用户维度的并发连接数上限控制（可选，`max_connections == 0` 表示不限制）；
     * @details - 统计用户维度的上下行流量字节数（通过原子计数器累加）。
     *
     * 线程安全性设计：
     * @details - 用户表采用 `std::atomic` + `std::shared_ptr` 进行只读无锁快照访问；
     * @details - 写入通过拷贝更新（`copy-on-write`），避免读路径阻塞；
     * @details - `traffic_metrics` 内部使用原子计数，避免转发路径上频繁加锁。
     *
     * ```
     * // 典型用法：启动阶段注入用户凭据，并在握手后申请配额
     * ngx::agent::validator validator;
     * validator.upsert_user("CREDENTIAL_1", 32);
     *
     * // 握手解析出凭据后：
     * auto guard = validator.try_acquire(credential);
     * if (!guard)
     * {
     *     // 超过并发上限或用户不存在
     *     co_return;
     * }
     *
     * // 在转发路径上做流量统计
     * ngx::agent::validator::accumulate_uplink(guard.state(), bytes);
     * ```
     */
    class validator
    {
    public:
        /**
         * @brief 构造验证器
         * @param resource 内存资源指针
         * @note 默认使用 `memory::system::global_pool()` 以确保跨线程访问安全（内部使用 atomic 和 shared_ptr）。
         * 请勿传入非线程安全的内存池（如 `unsynchronized_pool`），除非你确定只在单线程环境使用。
         */
        explicit validator(const memory::resource_pointer resource = memory::system::global_pool())
            : allocator_(resource), users_ptr_()
        {
            users_ptr_.store(std::allocate_shared<hash_map>(allocator_, 0));
        }

        /**
         * @brief 透明哈希（支持 `std::string_view` 查找）
         * @details 用于让 `users_` 支持以 `std::string_view` 在 `memory::unordered_map<memory::string, ...>` 上做透明查找，
         * 避免在校验路径上构造临时 `std::string`。
         * @note `is_transparent` 用于启用透明查找能力。
         */
        struct transparent_hash
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(std::string_view value) const noexcept -> std::size_t
            {
                return std::hash<std::string_view>{}(value);
            }

            [[nodiscard]] auto operator()(const std::string &value) const noexcept -> std::size_t
            {
                return std::hash<std::string_view>{}(std::string_view(value));
            }
        };

        /**
         * @brief 透明相等比较（支持 `std::string_view`）
         * @details 与 `transparent_hash` 配合，允许 `users_.find(credential_view)` 直接工作。
         */
        struct transparent_equal
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(std::string_view left, std::string_view right) const noexcept -> bool
            {
                return left == right;
            }

            [[nodiscard]] auto operator()(const std::string &left, std::string_view right) const noexcept -> bool
            {
                return std::string_view(left) == right;
            }

            [[nodiscard]] auto operator()(std::string_view left, const std::string &right) const noexcept -> bool
            {
                return left == std::string_view(right);
            }

            [[nodiscard]] auto operator()(const std::string &left, const std::string &right) const noexcept -> bool
            {
                return left == right;
            }
        };

        /**
         * @brief 用户状态统计结构
         * @details 该结构由 `validator` 持有并共享给多个会话：
         * @details - `uplink_bytes`：上行字节数累加
         * @details - `downlink_bytes`：下行字节数累加
         * @details - `active_connections`：当前活跃连接数
         * @details - `max_connections`：最大并发连接数（0 表示不限制）
         *
         * @note 所有计数采用原子类型，适配 `io_context` 多线程运行模式。
         */
        struct traffic_metrics
        {
            std::uint32_t max_connections{0};
            std::atomic_uint64_t uplink_bytes{0};
            std::atomic_uint64_t downlink_bytes{0};
            std::atomic_uint32_t active_connections{0};
        };

        /**
         * @class protector
         * @brief 配额守卫（`RAII`）
         * @details `protector` 用于确保连接配额格在会话结束时被正确归还：
         * @details - 构造时接管一个 `traffic_metrics` 的共享引用；
         * @details - 析构时对 `active_connections` 做减一；
         * @details - 该类型为可移动、不可拷贝，避免重复释放。
         *
         * @note 该守卫只负责“连接数配额”，不会关闭任何 `socket`。
         *
         * ```
         * auto guard = validator.try_acquire(credential);
         * if (!guard) { co_return; }
         *
         * // guard 生命周期覆盖整个会话
         * co_await handler::original_tunnel(ctx);
         * ```
         */
        class protector
        {
        public:
            protector() = default;

            explicit protector(std::shared_ptr<traffic_metrics> state) noexcept
                : state_(std::move(state))
            {
            }

            protector(protector &&other) noexcept
                : state_(std::move(other.state_))
            {
            }

            auto operator=(protector &&other) noexcept -> protector &
            {
                if (this == &other)
                {
                    return *this;
                }

                release();
                state_ = std::move(other.state_);
                return *this;
            }

            protector(const protector &) = delete;
            auto operator=(const protector &) -> protector & = delete;

            ~protector()
            {
                release();
            }

            [[nodiscard]] auto state() const noexcept -> traffic_metrics *
            {
                return state_.get();
            }

            [[nodiscard]] explicit operator bool() const noexcept
            {
                return static_cast<bool>(state_);
            }

        private:
            void release() noexcept
            {
                if (!state_)
                {
                    return;
                }

                state_->active_connections.fetch_sub(1, std::memory_order_relaxed);
                state_.reset();
            }

            std::shared_ptr<traffic_metrics> state_;
        };

        /**
         * @brief 预分配用户表容量
         * @param n 预期用户数量
         * @throws `std::bad_alloc` 当底层容器扩容分配失败时
         * @note 建议在启动阶段调用，避免运行期扩容带来的抖动。
         */
        void reserve(const std::size_t n)
        {
            auto reserve_func = [n](hash_map &ref)
            {
                ref.reserve(n);
            };
            update_users(reserve_func);
        }

        /**
         * @brief 清空用户表
         * @details 会释放所有用户状态；正在持有的 `protector` 仍会安全工作（共享指针语义）。
         * @note 该操作通常只应在重新加载配置时使用。
         */
        void clear()
        {
            users_ptr_.store(std::allocate_shared<hash_map>(allocator_, 0), std::memory_order_release);
        }

        /**
         * @brief 插入或更新用户
         * @details 若用户不存在则创建新的 `traffic_metrics`，并设置 `max_connections`。
         * @param credential 用户凭据（作为用户键）
         * @param max_connections 最大并发连接数；为 0 表示不限制
         * @throws `std::bad_alloc` 当插入/扩容导致内存分配失败时
         * @note 推荐在启动阶段批量调用，避免运行期更新用户表。
         */
        void upsert_user(std::string_view credential, const std::uint32_t max_connections = 0)
        {
            auto upsert = [credential, max_connections](hash_map &ref)
            {
                auto &state_pointer = ref[memory::string(credential, ref.get_allocator().resource())];
                if (!state_pointer)
                {
                    state_pointer = std::allocate_shared<traffic_metrics>(ref.get_allocator());
                }
                state_pointer->max_connections = max_connections;
            };
            update_users(upsert);
        }

        /**
         * @brief 校验用户是否存在
         * @param credential 用户凭据
         * @return 若存在返回 `true`，否则返回 `false`
         * @note 该函数仅做存在性判断，不会申请连接配额。
         */
        [[nodiscard]] auto verify(std::string_view credential) const noexcept -> bool
        {
            const auto users_snapshot = users_ptr_.load(std::memory_order_acquire);
            return users_snapshot && users_snapshot->find(credential) != users_snapshot->end();
        }

        /**
         * @brief 尝试申请一次连接配额
         * @details 申请流程：
         * @details - 若用户不存在则返回空守卫；
         * @details - 若 `max_connections == 0`，则直接递增活跃连接数；
         * @details - 否则使用 `compare_exchange_weak` 在并发场景下安全递增。
         * @param credential 用户凭据
         * @return 成功返回有效的 `protector`；失败返回空守卫
         * @note 返回的 `protector` 析构时会自动归还配额。
         */
        [[nodiscard]] auto try_acquire(std::string_view credential) const noexcept -> protector
        {
            const auto users_snapshot = users_ptr_.load(std::memory_order_acquire);
            if (!users_snapshot)
            {
                return {};
            }
            auto it = users_snapshot->find(credential);
            if (it == users_snapshot->end())
            {
                return {};
            }
            auto state_pointer = it->second;

            if (!state_pointer)
            {
                return {};
            }

            if (state_pointer->max_connections == 0)
            {
                state_pointer->active_connections.fetch_add(1, std::memory_order_relaxed);
                return protector(std::move(state_pointer));
            }

            auto current = state_pointer->active_connections.load(std::memory_order_relaxed);
            while (true)
            {
                if (current >= state_pointer->max_connections)
                {
                    return {};
                }
                if (state_pointer->active_connections.compare_exchange_weak(
                        current, current + 1, std::memory_order_relaxed, std::memory_order_relaxed))
                {
                    return protector(std::move(state_pointer));
                }
            }
        }

        /**
         * @brief 累加上行字节数
         * @param state 用户状态指针（可为 `nullptr`）
         * @param bytes 本次上行转发字节数
         * @note 该函数为无锁原子累加，适合放在转发热路径。
         */
        static void accumulate_uplink(traffic_metrics *state, const std::uint64_t bytes) noexcept
        {
            if (!state)
            {
                return;
            }
            state->uplink_bytes.fetch_add(bytes, std::memory_order_relaxed);
        }

        /**
         * @brief 累加下行字节数
         * @param state 用户状态指针（可为 `nullptr`）
         * @param bytes 本次下行转发字节数
         * @note 该函数为无锁原子累加，适合放在转发热路径。
         */
        static void accumulate_downlink(traffic_metrics *state, const std::uint64_t bytes) noexcept
        {
            if (!state)
            {
                return;
            }
            state->downlink_bytes.fetch_add(bytes, std::memory_order_relaxed);
        }

    private:
        using hash_map = memory::unordered_map<memory::string, std::shared_ptr<traffic_metrics>, transparent_hash, transparent_equal>;

        template <typename UpdateFn>
        void update_users(UpdateFn &&update_fn)
        {
            auto current = users_ptr_.load(std::memory_order_acquire);
            if (!current)
            {
                current = std::allocate_shared<hash_map>(allocator_, 0);
            }

            while (true)
            {
                auto next = std::allocate_shared<hash_map>(allocator_, *current);
                update_fn(*next);
                if (users_ptr_.compare_exchange_strong(current, next, std::memory_order_release, std::memory_order_acquire))
                {
                    return;
                }
            }
        }
        memory::allocator<std::byte> allocator_;
        std::atomic<std::shared_ptr<hash_map>> users_ptr_;
    };
} // namespace ngx::agent
