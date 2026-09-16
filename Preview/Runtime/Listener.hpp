/**
 * @file Listener.hpp
 * @brief TCP 监听器骨架（T4-3）
 * @details listener Accept → 亲和性分发（FNV-1a 哈希）→ 会话工厂：
 *          - Accept 循环：async_accept + 分发 + co_spawn 会话
 *          - 亲和性：同一远端地址 → 同一 worker（哈希稳定）
 *          - Stop()：取消 acceptor，Accept 循环退出
 * @note 对应生产 runtime/front/listener + balancer；worker 池执行
 *       模型简化（单 ioc），分发逻辑完整可测
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <chrono>
#include <exception>
#include <functional>
#include <atomic>
#include <limits>
#include <memory>
#include <string_view>
#include <utility>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Runtime/SessionRegistry.hpp>
#include <Preview/Runtime/WorkerGroup.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Runtime
{

    namespace Net = boost::asio;

    /**
     * @class AffinityBalancer
     * @brief 亲和性分发器
     * @details FNV-1a 哈希远端标识 → worker 索引。
     *          相同标识稳定映射（亲和），分布近似均匀。
     */
    class AffinityBalancer
    {
    public:
        /**
         * @brief 构造
         * @param WorkerCount worker 数（≥1）
         */
        explicit AffinityBalancer(std::size_t WorkerCount) : WorkerCount_(WorkerCount)
        {
            if (WorkerCount_ < 1)
            {
                WorkerCount_ = 1;
            }
        }

        /**
         * @brief 选择 worker
         * @param key 亲和性键（如远端地址）
         * @return worker 索引 [0, WorkerCount)
         */
        [[nodiscard]] auto Select(std::string_view key) const noexcept -> std::size_t
        {
            std::uint64_t Hash = 14695981039346656037ULL;
            for (const char c : key)
            {
                Hash ^= static_cast<unsigned char>(c);
                Hash *= 1099511628211ULL;
            }
            return static_cast<std::size_t>(Hash % WorkerCount_);
        }

        /**
         * @brief worker 数
         */
        [[nodiscard]] auto WorkerCount() const noexcept -> std::size_t
        {
            return WorkerCount_;
        }

    private:
        std::size_t WorkerCount_; ///< worker 数
    };

    /**
     * @class TcpListener
     * @brief TCP 监听器
     * @details 绑定端点后进入 Accept 循环，每个连接按远端地址
     *          亲和性分发到 worker 并启动会话。
     */
    class TcpListener
    {
    public:
        /// 会话工厂签名：入站传输 + worker 索引 → 会话
        using SessionFactory =
            std::function<std::shared_ptr<Session>(Preview::SharedTransmission, std::size_t)>;
        using FailureHandler = std::function<void(Preview::Fault::Code)>;

        struct Options final
        {
            Net::any_io_executor Executor;
            SessionFactory Factory;
            std::size_t WorkerCount{1};
            std::size_t MaxConnections{0};
            WorkerGroup *Workers{nullptr};
            Preview::ProcessId Process{};
            Preview::GenerationId Generation{};
            std::size_t MailboxCapacity{64};
            FailureHandler OnFailure;
        };

    private:
        struct Completion final
        {
            using Channel = Net::experimental::channel<void(boost::system::error_code)>;

            explicit Completion(Net::any_io_executor ExecutorValue)
                : Signal(std::move(ExecutorValue), 1)
            {
            }

            auto Reset() noexcept -> void
            {
                Completed.store(false, std::memory_order_release);
            }

            auto Complete() noexcept -> void
            {
                if (Completed.exchange(true, std::memory_order_acq_rel))
                {
                    return;
                }
                (void)Signal.try_send(boost::system::error_code{});
            }

            [[nodiscard]] auto IsComplete() const noexcept -> bool
            {
                return Completed.load(std::memory_order_acquire);
            }

            [[nodiscard]] auto Wait() -> Net::awaitable<void>
            {
                if (IsComplete())
                {
                    co_return;
                }
                boost::system::error_code Error;
                co_await Signal.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
            }

            Channel Signal;
            std::atomic<bool> Completed{true};
        };

        /**
         * @struct Lifetime
         * @brief detached accept loop 的共享状态
         * @details accept loop 不捕获 TcpListener 的 this；Stop 或析构后，
         *          状态对象仍由协程持有，直到取消完成。
         */
        struct Lifetime
        {
            explicit Lifetime(Options OptionsValue)
                : Ex(std::move(OptionsValue.Executor)), Factory(std::move(OptionsValue.Factory)),
                  OnFailure(std::move(OptionsValue.OnFailure)),
                  Workers(OptionsValue.Workers),
                  Balancer(Workers ? Workers->Size() : 1),
                  Generation(OptionsValue.Generation),
                  MaxConnections(OptionsValue.MaxConnections),
                  Acceptor(Ex),
                  AcceptCompletion(std::make_shared<Completion>(Ex))
            {
            }

            Net::any_io_executor Ex;
            SessionFactory Factory;
            FailureHandler OnFailure;
            WorkerGroup *Workers{nullptr};
            AffinityBalancer Balancer;
            Preview::GenerationId Generation{};
            SessionRegistry Registry;
            std::size_t MaxConnections{0};
            std::atomic<std::size_t> ActiveConnections{0};
            Net::ip::tcp::acceptor Acceptor;
            std::shared_ptr<Completion> AcceptCompletion;
            std::atomic<bool> Started{false};
            std::atomic<bool> AcceptLoopStarted{false};
            std::atomic<bool> Ready{false};
            std::atomic<bool> Failed{false};
            std::atomic<bool> Stopped{false}; ///< Stop/析构后禁止新会话进入工厂
        };

        /**
         * @struct AdmissionRequest
         * @brief listener 到 worker 的一次性值拥有 admission 请求
         * @details 请求未被 worker 消费时，析构路径负责关闭入站传输并释放并发槽位；
         *          request 不借用 accept loop 的局部变量，也不允许回退到 listener executor。
         */
        struct AdmissionRequest final
        {
            AdmissionRequest(Preview::SharedTransmission TransportValue,
                             SessionFactory FactoryValue,
                             std::shared_ptr<Lifetime> StateValue,
                             SessionInfo InfoValue,
                             std::size_t WorkerIndexValue,
                             Preview::WorkerId WorkerValue,
                             Preview::GenerationId GenerationValue)
                : Transport(std::move(TransportValue)),
                  Factory(std::move(FactoryValue)),
                  State(std::move(StateValue)),
                  Info(std::move(InfoValue)),
                  WorkerIndex(WorkerIndexValue),
                  Worker(WorkerValue),
                  Generation(GenerationValue)
            {
            }

            ~AdmissionRequest() noexcept
            {
                Reject();
            }

            AdmissionRequest(const AdmissionRequest &) = delete;
            auto operator=(const AdmissionRequest &) -> AdmissionRequest & = delete;

            auto Reject() noexcept -> void
            {
                if (!Pending)
                {
                    return;
                }
                Pending = false;
                CloseAcceptedTransport(Transport);
                ReleaseConnection(State);
            }

            [[nodiscard]] auto TakeTransport() noexcept -> Preview::SharedTransmission
            {
                Pending = false;
                return std::move(Transport);
            }

            Preview::SharedTransmission Transport;
            SessionFactory Factory;
            std::shared_ptr<Lifetime> State;
            SessionInfo Info;
            std::size_t WorkerIndex{0};
            Preview::WorkerId Worker{};
            Preview::GenerationId Generation{};
            bool Pending{true};
        };

    public:

        /**
         * @brief 构造
         * @param ex 执行器
         * @param factory 会话工厂
         * @param WorkerCount worker 数（用于分发）
         */
        explicit TcpListener(Options OptionsValue)
            : State_(std::make_shared<Lifetime>(std::move(OptionsValue)))
        {
        }

        TcpListener(Net::any_io_executor Executor, SessionFactory Factory)
            : TcpListener(Options{std::move(Executor), std::move(Factory), 1, 0})
        {
        }

        TcpListener(Net::any_io_executor Executor,
                    SessionFactory Factory,
                    std::size_t WorkerCount)
            : TcpListener(Options{std::move(Executor), std::move(Factory), WorkerCount, 0})
        {
        }

        TcpListener(const TcpListener &) = delete;
        auto operator=(const TcpListener &) -> TcpListener & = delete;
        TcpListener(TcpListener &&) = delete;
        auto operator=(TcpListener &&) -> TcpListener & = delete;

        /**
         * @brief 析构即停止监听（RAII）
         * @details 不依赖调用方显式 Stop()：关闭 acceptor 让 Accept 循环退出；
         *          detached 循环持有的共享状态在取消完成后自行释放。
         * @note 必须在执行器线程调用（与单 executor 约束一致）。
         */
        ~TcpListener()
        {
            Stop();
            State_->Registry.BeginShutdown();
        }

        /**
         * @brief 绑定并启动监听
         * @param BindEp 绑定端点（端口 0 = 随机）
         * @return 成功或 io_error
         */
        [[nodiscard]] auto Start(const Net::ip::tcp::endpoint &BindEp)
            -> Net::awaitable<Preview::Fault::Code>
        {
            const auto State = State_;
            if (State->Stopped.load(std::memory_order_acquire) ||
                State->Started.exchange(true, std::memory_order_acq_rel))
            {
                co_return Preview::Fault::Code::InvalidArgument; // 已停止：不允许重新启动
            }
            boost::system::error_code ec;
            State->Acceptor.open(BindEp.protocol(), ec);
            if (!ec)
            {
                State->Acceptor.set_option(Net::ip::tcp::acceptor::reuse_address(true), ec);
            }
            if (!ec)
            {
                State->Acceptor.bind(BindEp, ec);
            }
            if (!ec)
            {
                State->Acceptor.listen(Net::socket_base::max_listen_connections, ec);
            }
            if (ec)
            {
                boost::system::error_code CloseError;
                State->Acceptor.close(CloseError);
                State->Failed.store(true, std::memory_order_release);
                co_return Preview::Fault::Code::IoError;
            }
            State->AcceptCompletion->Reset();
            State->AcceptLoopStarted.store(true, std::memory_order_release);
            try
            {
                Net::co_spawn(State->Ex, AcceptLoop(State), Net::detached);
            }
            catch (...)
            {
                State->AcceptLoopStarted.store(false, std::memory_order_release);
                State->Failed.store(true, std::memory_order_release);
                boost::system::error_code CloseError;
                State->Acceptor.close(CloseError);
                co_return Preview::Fault::Code::IoError;
            }
            State->Ready.store(true, std::memory_order_release);
            co_return Preview::Fault::Code::Success;
        }

        /**
         * @brief 停止监听（关闭 acceptor，Accept 循环退出）
         */
        void Stop()
        {
            State_->Ready.store(false, std::memory_order_release);
            if (State_->Stopped.exchange(true, std::memory_order_acq_rel))
            {
                return; // 幂等
            }
            boost::system::error_code ec;
            State_->Acceptor.cancel(ec);
            State_->Acceptor.close(ec);
        }

        [[nodiscard]] auto IsReady() const noexcept -> bool
        {
            return State_->Ready.load(std::memory_order_acquire) &&
                   !State_->Stopped.load(std::memory_order_acquire) &&
                   !State_->Failed.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto IsFailed() const noexcept -> bool
        {
            return State_->Failed.load(std::memory_order_acquire);
        }

        /**
         * @brief 获取活动会话注册表
         * @return listener 所有的注册表引用
         */
        [[nodiscard]] auto Registry() noexcept -> SessionRegistry &
        {
            return State_->Registry;
        }

        /**
         * @brief 停止接收并取消、排空活动会话
         * @details Stop 只关闭 acceptor；Registry Shutdown 等待实际会话
         *          协程完成，不使用阻塞等待或固定 grace 时间。
         */
        [[nodiscard]] auto Shutdown() -> Net::awaitable<void>
        {
            Stop();
            if (State_->AcceptLoopStarted.load(std::memory_order_acquire))
            {
                co_await State_->AcceptCompletion->Wait();
            }
            co_await State_->Registry.Shutdown();
        }

        /**
         * @brief 本地端点
         */
        [[nodiscard]] auto LocalEndpoint() const -> Net::ip::tcp::endpoint
        {
            return State_->Acceptor.local_endpoint();
        }

        /**
         * @brief 返回连接并发上限
         * @return 0 表示不限制，否则为允许保持的活动 Session 数
         */
        [[nodiscard]] auto MaxConnections() const noexcept -> std::size_t
        {
            return State_->MaxConnections;
        }

    private:
        [[nodiscard]] static auto ReserveSessionId() noexcept -> Preview::SessionId
        {
            static std::atomic<std::uint64_t> Next{1};
            auto Candidate = Next.load(std::memory_order_relaxed);
            while (Candidate != 0)
            {
                const auto Following = Candidate == std::numeric_limits<std::uint64_t>::max()
                                           ? 0
                                           : Candidate + 1U;
                if (Next.compare_exchange_weak(
                        Candidate, Following, std::memory_order_relaxed,
                        std::memory_order_relaxed))
                {
                    return Preview::SessionId{Candidate};
                }
            }
            return {};
        }

        /**
         * @brief 运行并收口一个已登记会话
         * @details 使用具名协程函数保存所有参数，避免立即调用带捕获
         *          coroutine lambda 的临时 closure 生命周期问题。
         */
        [[nodiscard]] static auto RunSession(
            std::shared_ptr<Session> Sess,
            Preview::SharedTransmission Transport,
            std::shared_ptr<Lifetime> State,
            std::shared_ptr<SessionControl> Control,
            SessionRegistry::Registration Registration) -> Net::awaitable<void>
        {
            try
            {
                const auto Result = co_await Sess->Run(Transport);
                if (Preview::Fault::Failed(Result))
                {
                    Control->ReportError(Result);
                }
            }
            catch (...)
            {
                Control->ReportError(Preview::Fault::Code::IoError,
                                     std::current_exception());
            }
            Sess->Close();
            Registration.Reset();
            ReleaseConnection(State);
        }

        /**
         * @brief 在选定 worker executor 上执行一次 admission 请求
         * @details Factory、SessionControl 绑定、注册和 tracked start 均位于 worker command；
         *          accept loop 只负责发布该 command。
         */
        static auto StartSession(const std::shared_ptr<AdmissionRequest> &Request) -> void
        {
            if (!Request || !Request->State)
            {
                return;
            }

            auto *WorkerValue = Request->State->Workers
                                    ? Request->State->Workers->Find(Request->Worker)
                                    : nullptr;
            if (Request->State->Workers &&
                (!WorkerValue || !WorkerValue->IsAccepting()))
            {
                return;
            }

            const auto SessionId = Request->Info.Id;
            auto Transport = Request->TakeTransport();
            const auto Reject = [&Request, &Transport]
            {
                CloseAcceptedTransport(Transport);
                ReleaseConnection(Request->State);
            };
            try
            {
                std::shared_ptr<Session> Sess;
                if (Request->Factory)
                {
                    Sess = Request->Factory(Transport, Request->WorkerIndex);
                }
                if (!Sess)
                {
                    Reject();
                    return;
                }

                auto Control = Sess->Control();
                if (!Control)
                {
                    Reject();
                    return;
                }

                auto Registration =
                    Request->State->Registry.Register(std::move(Request->Info), Control);
                if (!Registration)
                {
                    Reject();
                    return;
                }

                if (WorkerValue)
                {
                    (void)Control->Bind(
                        WorkerValue->Executor(),
                        std::shared_ptr<Preview::Lifecycle::TaskRegistry>(
                            &WorkerValue->Resources().Tasks,
                            [](Preview::Lifecycle::TaskRegistry *) {}));
                }
                else
                {
                    (void)Control->Bind(Request->State->Ex);
                }
                Preview::Lifecycle::TaskRequest TaskRequest;
                TaskRequest.Identity.SessionId = Preview::SessionId{SessionId};
                TaskRequest.Identity.WorkerId = Request->Worker;
                TaskRequest.Identity.Generation = Request->Generation;
                TaskRequest.Cancel = [Transport] { CloseAcceptedTransport(Transport); };
                const auto Started = Control->Start(
                    std::move(TaskRequest),
                    RunSession(std::move(Sess), Transport, Request->State, Control,
                               std::move(Registration)));
                if (!Started)
                {
                    Reject();
                }
            }
            catch (...)
            {
                Reject();
            }
        }

        /**
         * @brief Accept 循环：接受 → 亲和性分发 → 启动会话
         */
        [[nodiscard]] static auto AcceptLoop(std::shared_ptr<Lifetime> State)
            -> Net::awaitable<void>
        {
            struct CompletionGuard final
            {
                explicit CompletionGuard(std::shared_ptr<Completion> CompletionValue)
                    : Value(std::move(CompletionValue))
                {
                }

                ~CompletionGuard() noexcept
                {
                    if (Value)
                    {
                        Value->Complete();
                    }
                }

                std::shared_ptr<Completion> Value;
            } Guard(State->AcceptCompletion);

            while (true)
            {
                boost::system::error_code ec;
                auto Sock = co_await State->Acceptor.async_accept(
                    Net::redirect_error(Net::use_awaitable, ec));
                if (ec)
                {
                    if (!State->Stopped.load(std::memory_order_acquire))
                    {
                        if (!State->Failed.exchange(true, std::memory_order_acq_rel))
                        {
                            State->Ready.store(false, std::memory_order_release);
                            if (State->OnFailure)
                            {
                                try
                                {
                                    State->OnFailure(Preview::Fault::Code::IoError);
                                }
                                catch (...)
                                {
                                }
                            }
                        }
                    }
                    co_return;
                }
                if (State->Stopped.load(std::memory_order_acquire))
                {
                    // 析构/Stop 后已接受的连接不再进入工厂
                    boost::system::error_code CloseError;
                    Sock.close(CloseError);
                    co_return;
                }
                if (!TryAcquireConnection(State))
                {
                    boost::system::error_code CloseError;
                    Sock.close(CloseError);
                    continue;
                }
                boost::system::error_code pec;
                const auto Remote = Sock.remote_endpoint(pec);
                std::string Peer;
                if (pec)
                {
                    Peer = "unknown";
                }
                else
                {
                    Peer = Remote.address().to_string();
                }
                const auto WorkerIndex = State->Balancer.Select(Peer);
                const auto Worker = Preview::WorkerId{
                    static_cast<std::uint64_t>(WorkerIndex + 1)};
                auto Transport = Preview::Transport::MakeReliable(std::move(Sock));
                if (!State->Factory ||
                    State->Stopped.load(std::memory_order_acquire))
                {
                    CloseAcceptedTransport(Transport);
                    ReleaseConnection(State);
                    if (State->Stopped.load(std::memory_order_acquire))
                    {
                        co_return;
                    }
                    continue;
                }

                SessionInfo Info;
                const auto SessionId = ReserveSessionId();
                if (!SessionId)
                {
                    CloseAcceptedTransport(Transport);
                    ReleaseConnection(State);
                    if (State->OnFailure)
                    {
                        try
                        {
                            State->OnFailure(Preview::Fault::Code::ResourceUnavailable);
                        }
                        catch (...)
                        {
                        }
                    }
                    continue;
                }
                Info.Id = SessionId.Value();
                Info.peer = Peer;
                Info.StartedAt = static_cast<std::uint64_t>(
                    std::chrono::steady_clock::now().time_since_epoch().count());
                auto Request = std::make_shared<AdmissionRequest>(
                    std::move(Transport), State->Factory, State, std::move(Info),
                    State->Workers ? WorkerIndex : WorkerIndex + 1U,
                    Worker, State->Workers ? State->Workers->Generation() : State->Generation);
                const auto Result = State->Workers
                                        ? State->Workers->Dispatch(
                                              Worker, Request->Generation,
                                              [Request] { StartSession(Request); })
                                        : Mailbox::Result::Accepted;
                if (Result != Mailbox::Result::Accepted)
                {
                    Request->Reject();
                    if (State->Stopped.load(std::memory_order_acquire))
                    {
                        co_return;
                    }
                }
                else if (!State->Workers)
                {
                    StartSession(Request);
                }
            }
        }

        static auto CloseAcceptedTransport(const Preview::SharedTransmission &Transport) -> void
        {
            if (Transport && Transport->IsOpen())
            {
                Transport->Cancel();
                Transport->Close();
            }
        }

        [[nodiscard]] static auto TryAcquireConnection(const std::shared_ptr<Lifetime> &State) noexcept -> bool
        {
            if (State->MaxConnections == 0)
            {
                return true;
            }
            auto Current = State->ActiveConnections.load(std::memory_order_relaxed);
            while (Current < State->MaxConnections &&
                   !State->ActiveConnections.compare_exchange_weak(
                       Current, Current + 1, std::memory_order_acquire, std::memory_order_relaxed))
            {
            }
            return Current < State->MaxConnections;
        }

        static auto ReleaseConnection(const std::shared_ptr<Lifetime> &State) noexcept -> void
        {
            if (State->MaxConnections != 0)
            {
                State->ActiveConnections.fetch_sub(1, std::memory_order_release);
            }
        }

        std::shared_ptr<Lifetime> State_; ///< accept loop 生命周期状态
    };

} // namespace Preview::Runtime
