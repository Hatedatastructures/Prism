/**
 * @file Listener.hpp
 * @brief TCP 监听、亲和性分发和会话 admission owner。
 * @details accept loop 只发布 worker command；Stop/析构关闭 acceptor，
 *          session 由 SessionControl 取消、delivery 和最终 close 收口。
 */
#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Transport/Transmission.hpp>
namespace Prism::Runtime
{
    namespace Net = boost::asio;
    class Session;
    class SessionRegistry;
    class WorkerGroup;
    class GenerationPublication;

    /** @brief 同一代次发布 pin、worker 身份和入站传输的会话准入输入。 */
    struct SessionAdmission
    {
        Prism::SharedTransmission Inbound;
        Prism::WorkerId Worker{};
        std::string SourceIp;
        Prism::Foundation::GenerationPin Generation;
    };

    using SessionAdmissionResult =
        std::expected<std::shared_ptr<Session>, Prism::Fault::Failure>;

    /**
     * @class TcpListener
     * @brief TCP 监听器
     * @details 绑定端点后进入 Accept 循环，每个连接按远端地址
     *          亲和性分发到 worker 并启动会话。
     */
    class TcpListener
    {
    public:
        /// 会话工厂签名：传入远端 IP 仅在调用期间借用；会话需自行复制以延长生命周期。
        using SessionFactory = std::function<SessionAdmissionResult(SessionAdmission)>;
        using FailureHandler = std::function<void(Prism::Fault::Code)>;
        struct Options final
        {
            Net::any_io_executor Executor;
            SessionFactory Factory;
            std::size_t WorkerCount{1};
            std::size_t MaxConnections{0};
            /// 借用唯一 Process worker 集合；调用方必须保持其存活到 Shutdown 和已提交 admission 排空。
            WorkerGroup *Workers{nullptr};
            std::shared_ptr<GenerationPublication> Publication;
            Prism::ProcessId Process{};
            std::size_t MailboxCapacity{64};
            FailureHandler OnFailure;
        };
    private:
        struct Lifetime;
        struct AdmissionRequest;
        struct AcceptCompletionToken;

        [[nodiscard]] static auto StartOwned(std::shared_ptr<Lifetime> State,
            Net::ip::tcp::endpoint BindEp)
            -> Net::awaitable<Prism::Fault::Code>;
        [[nodiscard]] static auto ShutdownOwned(std::shared_ptr<Lifetime> State)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        static auto StopOwned(const std::shared_ptr<Lifetime> &State) noexcept -> void;
        static auto NotifyFailure(const std::shared_ptr<Lifetime> &State,
            Prism::Fault::Code Code) noexcept -> void;
    public:
        /** @brief 构造 listener owner；Options 接管 factory 和 worker 配置。 */
        explicit TcpListener(Options OptionsValue);
        TcpListener(const TcpListener &) = delete;
        auto operator=(const TcpListener &) -> TcpListener & = delete;
        TcpListener(TcpListener &&) = delete;
        auto operator=(TcpListener &&) -> TcpListener & = delete;
        /**
         * @brief 析构即请求 listener shutdown（RAII）
         * @details 停止接受新连接、封止会话注册，并向当前活动会话请求
         *          shutdown 取消；不等待会话或 detached 操作物理排空。
         * @note 必须在执行器线程调用（与单 executor 约束一致）。
         */
        ~TcpListener() noexcept;
        /**
         * @brief 绑定并启动监听
         * @param BindEp 绑定端点（端口 0 = 随机）
         * @return 成功或 io_error
         */
        [[nodiscard]] auto Start(const Net::ip::tcp::endpoint &BindEp)
            -> Net::awaitable<Prism::Fault::Code>;
        /**
         * @brief 停止监听（关闭 acceptor，Accept 循环退出）
         */
        void Stop() noexcept;
        [[nodiscard]] auto IsReady() const noexcept -> bool;
        [[nodiscard]] auto IsFailed() const noexcept -> bool;
        /**
         * @brief 获取活动会话注册表
         * @return listener 所有的注册表引用
         */
        [[nodiscard]] auto Registry() noexcept -> SessionRegistry &;
        /**
         * @brief 停止接收并取消、排空活动会话
         * @details Stop 只关闭 acceptor；Registry Shutdown 等待实际会话
         *          子 scope；连接屏障等待已接收 admission 与拒绝 owner 退栈。
         *          独立 listener root 另行等待会话 runner 的真实 completion handler 退栈。
         */
        [[nodiscard]] auto Shutdown()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        /**
         * @brief 本地端点
         */
        [[nodiscard]] auto LocalEndpoint() const -> Net::ip::tcp::endpoint;
        /**
         * @brief 返回连接并发上限
         * @return 0 表示不限制，否则为允许保持的活动 Session 数
         */
        [[nodiscard]] auto MaxConnections() const noexcept -> std::size_t;
    private:
        static auto RejectAdmission(const std::shared_ptr<AdmissionRequest> &Request,
                                    const std::shared_ptr<Session> &SessionOwner) noexcept -> void;

        /** @brief 在选定 worker executor 上完成 factory、registry 和 tracked start。 */
        static auto StartSession(const std::shared_ptr<AdmissionRequest> &Request) -> void;
        [[nodiscard]] static auto AcceptLoop(std::shared_ptr<Lifetime> State)
            -> Net::awaitable<void>;
        std::shared_ptr<Lifetime> State_; ///< accept loop 生命周期状态
    };
} // namespace Prism::Runtime
