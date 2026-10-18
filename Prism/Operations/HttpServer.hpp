/**
 * @file HttpServer.hpp
 * @brief Prism Operations loopback HTTP/1.1 管理监听器。
 */

#pragma once

#include <Prism/Operations/Router.hpp>
#include <Prism/Operations/Web/Catalog.hpp>
#include <Prism/Operations/Http/Limits.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

#include <openssl/crypto.h>

#include <chrono>
#include <atomic>
#include <memory>
#include <optional>
#include <utility>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>

namespace Prism::Operations
{

    namespace Net = boost::asio;


    /**
     * @brief 已解析管理请求的非拥有视图。
     * @details 所有 string_view 均借用连接协程拥有的原始请求缓冲，只在该请求的路由
     *          awaitable 完成前有效；handler 不得把这些视图保存到后续请求或独立任务。
     */
    struct HttpRequest final
    {
        std::string_view Method{};
        std::string_view Target{};
        std::string_view Correlation{};
        std::string_view Host{};
        std::string_view Origin{};
        std::string_view Authorization{};
        std::string_view ContentType{};
        std::string_view Body{};
        std::size_t HeaderEnd{0};
        std::size_t ContentLength{0};
        bool ContentLengthSeen{false};
    };

    /**
     * @class HttpServer
     * @brief executor-affine、单请求单连接的 Operations HTTP/1.1 listener。
     * @details StateStrand 拥有 listener、连接 registry 和 drain 状态；每个连接的
     *          socket 操作由独立 connection strand 串行化，connection owner 负责 socket
     *          最终关闭。Executor/context 由调用方持有，必须运行至 Drain 成功或失败被
     *          上层 owner 保留。析构只投递强制关闭，不等待连接任务退栈。
     */
    class HttpServer final
    {
    public:
        using Endpoint = Net::ip::tcp::endpoint;
        using StartResult = std::expected<Endpoint, boost::system::error_code>;
        using Deadline = std::chrono::steady_clock::time_point;

        struct DrainResult final
        {
            Prism::Fault::Failure Failure{};
            std::size_t RemainingConnections{0};
        };

        /**
         * @brief listener 冷启动配置。
         * @details Executor 只借用其调度域，不拥有 io_context；Router 按值复制，
         *          Bootstrap 与 WebResources 共享只读 owner，直至 listener 退栈。
         */
        struct Options final
        {
            Net::any_io_executor Executor;
            Endpoint BindEndpoint;
            Router OperationsRouter;
            std::chrono::milliseconds ReadDeadline{std::chrono::milliseconds{5000}};
            std::chrono::milliseconds DrainTimeout{std::chrono::milliseconds{5000}};
            std::shared_ptr<const BootstrapIdentity> Bootstrap;
            std::shared_ptr<const Web::Catalog> WebResources;
        };

        /** @brief 按值语义复制冷配置并创建 listener state owner。 */
        explicit HttpServer(const Options &OptionsValue);

        /** @brief 投递最佳努力关闭；不等待连接退栈，正常关闭必须先 await Drain。 */
        ~HttpServer() noexcept;

        HttpServer(const HttpServer &) = delete;
        auto operator=(const HttpServer &) -> HttpServer & = delete;
        HttpServer(HttpServer &&) = delete;
        auto operator=(HttpServer &&) -> HttpServer & = delete;

        /**
         * @brief 在 Options.Executor 上绑定 endpoint 并启动 accept loop。
         * @details listener 接管已接受 socket 和连接任务；expected 返回值报告 loopback
         *          验证或 socket setup 错误。executor 调度产生的异常沿协程异常路径传播。
         *          调用方须持有 HttpServer 与外部 executor 至 Drain 完成。
         */
        [[nodiscard]] auto Start() -> Net::awaitable<StartResult>;

        /**
         * @brief 向唯一 state strand 提交关闭新连接准入。
         * @details 成功只表示关闭命令已排队；不会关闭已接受 socket，最终完成由 Drain 回报。
         */
        [[nodiscard]] auto CloseAdmission() noexcept
            -> std::expected<void, Prism::Fault::Failure>;

        /**
         * @brief 关闭准入、等待活动请求真实退栈，deadline 后才强制关闭剩余连接。
         * @param Limit 调用方持有的绝对停机截止时间；本操作不会延长该预算。
         * @return Drained 表示所有连接完成响应并退栈；其他状态保留真实失败和剩余数。
         * @note awaitable 被调用方取消时，已关闭的 admission 不会重开；调用方仍须持有
         *       server，并继续 Drain 或把失败 owner 保留到进程终态处理。
         */
        [[nodiscard]] auto Drain(Deadline Limit) -> Net::awaitable<DrainResult>;

        /** @brief 按值读取最近一次成功 Start 的绑定端点；不转移 acceptor 所有权。 */
        [[nodiscard]] auto LocalEndpoint() const -> Endpoint;

        /** @brief 读取 listener admission/running 状态；不代表连接任务已退栈。 */
        [[nodiscard]] auto IsRunning() const noexcept -> bool;

    private:
        struct State;

        [[nodiscard]] static auto DrainOnState(std::shared_ptr<State> StateValue,
                                               Deadline Limit)
            -> Net::awaitable<DrainResult>;
        auto ForceCloseOnDestruction() noexcept -> void;

        std::shared_ptr<State> State_;
    };


} // namespace Prism::Operations

namespace Prism::Operations::HttpDetail::RequestSecurity
{

    /** @brief 按实际 loopback endpoint 构造唯一 IP literal authority。 */
    [[nodiscard]] inline auto MakeAuthority(const HttpServer::Endpoint &Endpoint)
        -> std::optional<std::string>
    {
        const auto AddressValue = Endpoint.address();
        if (!AddressValue.is_loopback())
        {
            return std::nullopt;
        }
        auto Authority = AddressValue.to_string();
        if (AddressValue.is_v6())
        {
            Authority = "[" + Authority + "]";
        }
        Authority.append(":").append(std::to_string(Endpoint.port()));
        return Authority;
    }

    /** @brief 将十六进制字符解码为半字节；非法字符返回哨兵值。 */
    [[nodiscard]] inline auto HexNibble(const char Value) noexcept -> std::uint8_t
    {
        if (Value >= '0' && Value <= '9')
        {
            return static_cast<std::uint8_t>(Value - '0');
        }
        if (Value >= 'a' && Value <= 'f')
        {
            return static_cast<std::uint8_t>(Value - 'a' + 10);
        }
        if (Value >= 'A' && Value <= 'F')
        {
            return static_cast<std::uint8_t>(Value - 'A' + 10);
        }
        return 0xffU;
    }

    /** @brief 用 BoringSSL constant-time 比较固定长度 bearer token。 */
    [[nodiscard]] inline auto HasValidCommandToken(
        const HttpRequest &Request,
        const BootstrapIdentity &Identity) noexcept -> bool
    {
        constexpr std::string_view Prefix{"Bearer "};
        constexpr auto TokenBytes = BootstrapIdentity::CommandToken{}.size();
        if (Request.Authorization.size() != Prefix.size() + TokenBytes * 2U ||
            !Request.Authorization.starts_with(Prefix))
        {
            return false;
        }
        BootstrapIdentity::CommandToken Candidate{};
        bool ValidHex = true;
        for (std::size_t Index = 0; Index < Candidate.size(); ++Index)
        {
            const auto High = HexNibble(Request.Authorization[Prefix.size() + Index * 2U]);
            const auto Low = HexNibble(Request.Authorization[Prefix.size() + Index * 2U + 1U]);
            ValidHex = ValidHex && High < 16U && Low < 16U;
            Candidate[Index] = static_cast<std::uint8_t>(
                ((High & 0x0fU) << 4U) | (Low & 0x0fU));
        }
        const auto Equal = CRYPTO_memcmp(
            Candidate.data(), Identity.Token().data(), Candidate.size()) == 0;
        return ValidHex && Equal;
    }

    /** @brief 校验 loopback Host、可选同源 Origin 与 POST 命令 token。 */
    [[nodiscard]] inline auto IsAuthorized(
        const HttpRequest &Request,
        const HttpServer::Endpoint &LocalEndpoint,
        const BootstrapIdentity &Identity) -> bool
    {
        const auto Authority = MakeAuthority(LocalEndpoint);
        if (!Authority || Request.Host != *Authority)
        {
            return false;
        }
        if (!Request.Origin.empty() && Request.Origin != "http://" + *Authority)
        {
            return false;
        }
        return Request.Method != "POST" || HasValidCommandToken(Request, Identity);
    }

} // namespace Prism::Operations::HttpDetail::RequestSecurity

#include <Prism/Operations/HttpConnection.hpp>

namespace Prism::Operations
{
    using Tcp = Net::ip::tcp;

    struct HttpServer::State final
    {
        explicit State(Options OptionsValue)
            : Executor(std::move(OptionsValue.Executor)),
              StateStrand(Net::make_strand(Executor)),
              BindEndpoint(OptionsValue.BindEndpoint),
              OperationsRouter(std::move(OptionsValue.OperationsRouter)),
              ReadDeadline(OptionsValue.ReadDeadline),
              DrainTimeout(OptionsValue.DrainTimeout),
              Bootstrap(std::move(OptionsValue.Bootstrap)),
              WebResources(std::move(OptionsValue.WebResources)),
              Acceptor(StateStrand),
              DrainTimer(StateStrand)
        {
        }

        Net::any_io_executor Executor;
        Net::strand<Net::any_io_executor> StateStrand;
        Endpoint BindEndpoint;
        Endpoint LocalEndpoint{};
        Router OperationsRouter;
        std::chrono::milliseconds ReadDeadline;
        std::chrono::milliseconds DrainTimeout;
        std::shared_ptr<const BootstrapIdentity> Bootstrap;
        std::shared_ptr<const Web::Catalog> WebResources;
        std::shared_ptr<HttpConnection::RequestByteBudget> RequestBudget{
            std::make_shared<HttpConnection::RequestByteBudget>()};
        std::vector<std::shared_ptr<HttpConnection::ConnectionState>> ActiveConnections;
        Tcp::acceptor Acceptor;
        Net::steady_timer DrainTimer;
        std::optional<std::chrono::steady_clock::time_point> DrainDeadline;
        std::optional<Prism::Fault::Failure> DrainFailure;
        bool DrainTimerArmed{false};
        bool DrainTimerExpired{false};
        std::atomic<std::size_t> ActiveConnectionCount{0};
        std::atomic<std::uint64_t> NextCorrelation{1};
        std::atomic<bool> Started{false};
        std::atomic<bool> Running{false};
        std::atomic<bool> StopRequested{false};
        std::atomic<bool> Draining{false};
        std::atomic<bool> Drained{false};
        std::atomic<bool> StateOperationFailed{false};
    };

    inline HttpServer::HttpServer(const Options &OptionsValue)
        : State_(std::make_shared<State>(OptionsValue))
    {
    }

    inline HttpServer::~HttpServer() noexcept
    {
        ForceCloseOnDestruction();
    }

    inline auto HttpServer::Start() -> Net::awaitable<StartResult>
    {
        const auto StateValue = State_;
        if (!StateValue->Bootstrap)
        {
            co_return std::unexpected(
                boost::system::errc::make_error_code(boost::system::errc::invalid_argument));
        }
        co_await Net::post(StateValue->StateStrand, Net::use_awaitable);
        co_return HttpConnection::StartOnStateStrand(StateValue);
    }

    inline auto HttpServer::CloseAdmission() noexcept
        -> std::expected<void, Prism::Fault::Failure>
    {
        const auto StateValue = State_;
        try
        {
            Net::post(
                StateValue->StateStrand,
                [StateValue]
                {
                    StateValue->StopRequested.store(true, std::memory_order_release);
                    HttpConnection::CloseAdmissionOnStateStrand(StateValue);
                });
        }
        catch (...)
        {
            StateValue->StateOperationFailed.store(true, std::memory_order_release);
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        return {};
    }

    inline auto HttpServer::ForceCloseOnDestruction() noexcept -> void
    {
        const auto StateValue = State_;
        try
        {
            Net::post(
                StateValue->StateStrand,
                [StateValue]
                {
                    if (!StateValue->StopRequested.exchange(true, std::memory_order_acq_rel))
                    {
                        HttpConnection::CloseOnStateStrand(StateValue);
                    }
                });
        }
        catch (...)
        {
            StateValue->Started.store(false, std::memory_order_release);
            StateValue->Running.store(false, std::memory_order_release);
            StateValue->StopRequested.store(true, std::memory_order_release);
            StateValue->StateOperationFailed.store(true, std::memory_order_release);
        }
    }

    inline auto HttpServer::Drain(const Deadline Limit) -> Net::awaitable<DrainResult>
    {
        return DrainOnState(State_, Limit);
    }

    inline auto HttpServer::DrainOnState(std::shared_ptr<State> StateValue,
                                         const Deadline Limit)
        -> Net::awaitable<DrainResult>
    {
        co_await Net::post(StateValue->StateStrand, Net::use_awaitable);
        StateValue->StopRequested.store(true, std::memory_order_release);
        StateValue->Draining.store(true, std::memory_order_release);
        HttpConnection::CloseAdmissionOnStateStrand(StateValue);
        const auto ConfiguredDeadline = std::chrono::steady_clock::now() + StateValue->DrainTimeout;
        if (!StateValue->DrainDeadline)
        {
            StateValue->DrainDeadline = std::min(Limit, ConfiguredDeadline);
        }
        else
        {
            StateValue->DrainDeadline = std::min(*StateValue->DrainDeadline, Limit);
        }

        while (true)
        {
            const auto RemainingConnections =
                StateValue->ActiveConnectionCount.load(std::memory_order_acquire);
            if (StateValue->StateOperationFailed.load(std::memory_order_acquire))
            {
                HttpConnection::CloseConnectionsOnStateStrand(StateValue);
                auto Failure = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
                if (StateValue->DrainFailure) Failure = *StateValue->DrainFailure;
                co_return DrainResult{Failure, RemainingConnections};
            }
            if (RemainingConnections == 0U)
            {
                StateValue->Drained.store(true, std::memory_order_release);
                co_return DrainResult{{}, 0U};
            }
            if (StateValue->DrainTimerExpired ||
                std::chrono::steady_clock::now() >= *StateValue->DrainDeadline)
            {
                StateValue->DrainTimerExpired = true;
                HttpConnection::CloseConnectionsOnStateStrand(StateValue);
                co_return DrainResult{
                    Prism::Fault::Failure{Prism::Fault::Code::Timeout,
                        std::make_error_code(std::errc::timed_out)},
                    RemainingConnections};
            }
            if (!StateValue->DrainTimerArmed)
            {
                StateValue->DrainTimer.expires_at(*StateValue->DrainDeadline);
                StateValue->DrainTimerArmed = true;
            }

            boost::system::error_code Error;
            co_await StateValue->DrainTimer.async_wait(
                Net::redirect_error(Net::use_awaitable, Error));
            StateValue->DrainTimerArmed = false;
            if (Error && Error != Net::error::operation_aborted)
            {
                const auto RemainingAfterWait =
                    StateValue->ActiveConnectionCount.load(std::memory_order_acquire);
                HttpConnection::CloseConnectionsOnStateStrand(StateValue);
                co_return DrainResult{
                    Prism::Fault::FromNative(static_cast<std::error_code>(Error)),
                    RemainingAfterWait};
            }
            if (!Error)
            {
                StateValue->DrainTimerExpired = true;
            }
        }
    }

    inline auto HttpServer::LocalEndpoint() const -> Endpoint
    {
        return State_->LocalEndpoint;
    }

    inline auto HttpServer::IsRunning() const noexcept -> bool
    {
        return State_->Running.load(std::memory_order_acquire) &&
               !State_->StopRequested.load(std::memory_order_acquire);
    }

} // namespace Prism::Operations
