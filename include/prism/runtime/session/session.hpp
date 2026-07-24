/**
 * @file session.hpp
 * @brief 连接会话编排模块
 * @details 会话对象持 shared_ptr<session_resources>，通过 shared_from_this
 *          支持异步回调自我保活。会话从入站传输层执行协议检测后分派到对应
 *          管道入口，无匹配则回退到原始透传。
 */

#pragma once

#include <prism/resource/session.hpp>
#include <prism/trace/context.hpp>

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
        inline std::atomic<std::uint64_t> conn_counter{0};

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
        std::shared_ptr<psm::resource::session> res;
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
            active,
            closing,
            closed
        };

        explicit session(session_params params);
        ~session() noexcept;

        auto start() -> void;
        auto close() -> void;

        auto set_on_closed(std::function<void()> callback) noexcept -> void
        {
            on_closed_ = std::move(callback);
        }

        [[nodiscard]] auto id() const noexcept -> std::uint64_t
        {
            return res_->conn;
        }

        [[nodiscard]] auto resources() const noexcept
            -> std::shared_ptr<psm::resource::session>
        {
            return res_;
        }

    private:
        auto diversion() -> net::awaitable<void>;
        auto release_resources() noexcept -> void;

        std::shared_ptr<psm::resource::session> res_;
        state state_{state::active};
        std::function<void()> on_closed_;
        std::unique_ptr<net::steady_timer> handshake_deadline_;
    };

    [[nodiscard]] auto make_session(session_params &&params) -> std::shared_ptr<session>;

} // namespace psm::runtime::session
