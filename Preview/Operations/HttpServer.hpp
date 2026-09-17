/**
 * @file HttpServer.hpp
 * @brief Preview Operations loopback HTTP/1.1 管理监听器。
 */

#pragma once

#include <Preview/Operations/Router.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string_view>

namespace Preview::Operations
{

    namespace Net = boost::asio;

    inline constexpr std::size_t MaxRequestBytes = 16U * 1024U;
    inline constexpr std::size_t MaxRequestLineBytes = 2048U;
    inline constexpr std::size_t MaxHeaderCount = 32U;
    inline constexpr std::size_t MaxResponseBytes = 256U * 1024U;

    enum class ParseStatus : std::uint8_t
    {
        Complete,
        Incomplete,
        Malformed,
        Oversized,
    };

    struct HttpRequest final
    {
        std::string_view Method{};
        std::string_view Target{};
        std::string_view Correlation{};
        std::size_t HeaderEnd{0};
        std::size_t ContentLength{0};
    };

    /**
     * @brief 解析一个不含正文的 HTTP/1.1 管理请求。
     * @details 输入必须是完整头块；未收到终止符时返回 Incomplete，超过固定上限
     *          时返回 Oversized。解析结果只借用输入视图。
     */
    [[nodiscard]] auto ParseRequest(std::string_view Raw, HttpRequest &Request) -> ParseStatus;

    /**
     * @class HttpServer
     * @brief executor-affine、单请求单连接的 Operations HTTP/1.1 listener。
     * @details listener、连接协程和 drain 计数均由共享状态拥有；协程不捕获本对象
     *          指针，Stop、Close、Drain 均可重复调用。
     */
    class HttpServer final
    {
    public:
        using Endpoint = Net::ip::tcp::endpoint;
        using StartResult = std::expected<Endpoint, boost::system::error_code>;

        struct Options final
        {
            Net::any_io_executor Executor;
            Endpoint BindEndpoint;
            Router OperationsRouter;
            std::chrono::milliseconds ReadDeadline{std::chrono::milliseconds{5000}};
        };

        explicit HttpServer(const Options &OptionsValue);

        HttpServer(Net::any_io_executor Executor,
                   Endpoint BindEndpoint,
                   const Router &OperationsRouter,
                   std::chrono::milliseconds ReadDeadline = std::chrono::milliseconds{5000});

        ~HttpServer() noexcept;

        HttpServer(const HttpServer &) = delete;
        auto operator=(const HttpServer &) -> HttpServer & = delete;
        HttpServer(HttpServer &&) = delete;
        auto operator=(HttpServer &&) -> HttpServer & = delete;

        /** @brief 在 listener executor 上绑定并启动 accept loop。 */
        [[nodiscard]] auto Start() -> Net::awaitable<StartResult>;

        /** @brief 停止接收新连接；重复调用无副作用。 */
        auto Stop() noexcept -> void;

        /** @brief Stop 的语义别名，保持管理面关闭 API 对称。 */
        auto Close() noexcept -> void;

        /** @brief 停止接收并等待已接受连接完成。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<void>;

        [[nodiscard]] auto LocalEndpoint() const -> Endpoint;

        [[nodiscard]] auto IsRunning() const noexcept -> bool;

    private:
        struct State;

        std::shared_ptr<State> State_;
    };

} // namespace Preview::Operations
