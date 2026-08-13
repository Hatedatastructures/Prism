/**
 * @file session.hpp
 * @brief 连接会话编排模块
 * @details 会话对象持 shared_ptr<session_resources>，通过 shared_from_this
 *          支持异步回调自我保活。会话从入站传输层执行协议检测后分派到对应
 *          管道入口，无匹配则回退到原始透传。
 */

#pragma once

#include <prism/diagnose/context.hpp>
#include <prism/resource/session.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <functional>
#include <memory>
#include <utility>

namespace psm::runtime::session
{

    namespace net = boost::asio;

    namespace detail
    {
        inline std::atomic<std::uint64_t> conn_counter{0}; ///< 全局连接号计数器

        /**
         * @brief 生成下一个会话连接号
         * @return 单调递增的连接号
         */
        [[nodiscard]] inline auto next_conn_id() noexcept -> std::uint64_t
        {
            return ++conn_counter;
        }
    } // namespace detail

    /**
     * @struct session_params
     * @brief 会话初始化参数集合
     */
    struct session_params
    {
        std::shared_ptr<psm::resource::session> res; ///< 会话资源（L3）
    };

    /**
     * @class session
     * @brief 代理连接会话管理器
     * @details 会话是单个代理连接的完整生命周期管理者，从入站连接建立开始，
     *          经过协议检测、管道分派、数据转发，直到连接关闭结束。会话对象
     *          通过 enable_shared_from_this 支持异步回调中的自我保活。
     */
    class session : public std::enable_shared_from_this<session>
    {
    public:
        enum class state : std::uint8_t
        {
            active,  ///< 运行中
            closing, ///< 关闭中
            closed   ///< 已关闭
        };

        /**
         * @brief 构造会话
         * @param params 会话初始化参数
         */
        explicit session(session_params params);
        /**
         * @brief 析构会话
         */
        ~session() noexcept;

        /**
         * @brief 启动会话处理流程
         */
        auto start() -> void;
        /**
         * @brief 关闭会话
         */
        auto close() -> void;

        /**
         * @brief 注册会话关闭回调
         * @param callback 关闭回调函数
         */
        auto set_on_closed(std::function<void()> callback) noexcept -> void
        {
            on_closed_ = std::move(callback);
        }

        /**
         * @brief 获取会话 ID
         * @return 全局唯一的连接号
         */
        [[nodiscard]] auto id() const noexcept -> std::uint64_t
        {
            return res_->conn;
        }

        /**
         * @brief 获取会话资源
         * @return 会话资源共享指针
         */
        [[nodiscard]] auto resources() const noexcept -> std::shared_ptr<psm::resource::session>
        {
            return res_;
        }

    private:
        /**
         * @brief 协议检测与分派协程
         * @return 协程对象，检测协议后分派到对应管道入口
         */
        auto diversion() -> net::awaitable<void>;
        /**
         * @brief 释放会话资源
         */
        auto release_resources() noexcept -> void;

        std::shared_ptr<psm::resource::session> res_; ///< 会话资源（L3）
        state state_{state::active};                  ///< 会话状态
        std::function<void()> on_closed_;             ///< 关闭回调
        std::unique_ptr<net::steady_timer> handshake_deadline_; ///< 握手超时定时器
    };

    /**
     * @brief 创建会话实例
     * @param params 会话初始化参数
     * @return 会话共享指针
     */
    [[nodiscard]] auto make_session(session_params &&params) -> std::shared_ptr<session>;

} // namespace psm::runtime::session
