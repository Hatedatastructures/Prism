/**
 * @file UpstreamState.hpp
 * @brief DNS 多上游查询的共享状态所有者
 * @details 共享状态持有上游配置、请求报文 ID 和多上游调度状态；单上游
 *          端点解析、传输查询、连接池和超时由 QueryExecutor 所有者管理。
 */

#pragma once

#include <Preview/Foundation/Fault/Compatible.hpp>
#include <Preview/Net/Dns/Answer.hpp>
#include <Preview/Net/Dns/Detail/Fallback.hpp>
#include <Preview/Net/Dns/Detail/QueryExecutor.hpp>
#include <Preview/Net/Dns/Detail/ResolverFailure.hpp>
#include <Preview/Net/Dns/QueryIdentity.hpp>
#include <Preview/Net/Dns/QueryIds.hpp>
#include <Preview/Net/Dns/Types.hpp>

#include <boost/asio.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <atomic>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <expected>
#include <memory>
#include <string>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace Preview::Network::Dns
{
    class Upstream;
}

namespace Preview::Network::Dns::Detail
{

    namespace Net = boost::asio;

    /**
     * @brief DNS 查询在异步边界接管的输入及调用对象所有权。
     * @details Domain 自有；FacadeOwner 非空表示公开 Upstream 原本由 shared_ptr 持有，
     *          以保留多上游并发查询的既有所有权前提。
     */
    struct UpstreamResolveRequest final
    {
        std::string Domain;
        QType QueryType;
        std::shared_ptr<Preview::Network::Dns::Upstream> FacadeOwner;
    };

    /**
     * @class UpstreamState
     * @brief 异步 DNS 多上游查询的共享状态所有者
     * @details ResolveOwned 按值接管输入并转为拥有型 DomainName；编码查询和 ID reservation 由一次
     *          EncodedQuery 保持到各传输任务真实完成。结果以 QueryResult 返回，传输错误保留
     *          boost::system::error_code；并发策略取消并等待未选中任务退栈，真实 socket 关闭仍由
     *          QueryExecutor 与连接池 owner 决定。DNS 查询不暴露流式半关闭；所有状态操作须在
     *          同一串行 executor/strand 上交错执行。
     * @note 非线程安全；状态设置与查询必须由同一串行 executor/strand 交错调用，
     *       单个 io_context 的多线程 run 不构成该合同。Resolver 通过 Serial_ 提供此串行域；并发查询 worker
     *       以共享指针保持批次状态。
     */
    class UpstreamState final
    {
    public:
        /**
         * @brief 构造查询客户端
         * @param Executor 执行器
         * @param Options 上游服务器、策略、超时和连接池配置
         */
        explicit UpstreamState(Net::any_io_executor Executor, UpstreamOptions Options = {})
            : Ex_(std::move(Executor)), Servers_(std::move(Options.Servers)), Mode_(Options.QueryMode),
              Query_(Ex_, QueryExecutorOptions{Options.MaxConnsPerServer,
                                                       Options.MaxIdleConnsPerPool,
                                                       Options.DefaultTimeout})
        {
        }

        /**
         * @brief 替换上游服务器列表
         * @param Servers 新列表
         */
        void SetServers(const std::vector<Server> &Servers)
        {
            Servers_ = Servers;
        }

        /**
         * @brief 设置解析策略
         * @param QueryMode Fallback、First 或 Fastest
         */
        void SetMode(const Mode QueryMode)
        {
            Mode_ = QueryMode;
        }

        /**
         * @brief 设置默认超时
         * @param Timeout 毫秒数
         */
        void SetTimeout(const std::chrono::milliseconds Timeout)
        {
            Query_.SetTimeout(Timeout);
        }

        /**
         * @brief 返回当前上游数量
         * @return 上游服务器列表大小
         */
        [[nodiscard]] auto ServerCount() const -> std::size_t
        {
            return Servers_.size();
        }

        /**
         * @brief 返回闲置连接总数
         * @return TCP、DoT、DoH 三池合计的闲置连接数
         */
        [[nodiscard]] auto IdleConnCount() const -> std::size_t
        {
            return Query_.IdleConnCount();
        }

        /**
         * @brief 清理全部过期闲置连接
         * @return 清理数量
         */
        auto ClearIdleConns() -> std::size_t
        {
            return Query_.ClearIdleConns();
        }


        /**
         * @brief 在返回 awaitable 前接管状态、域名和原门面所有者。
         * @param Owner 共享持有查询状态；覆盖本协程及全部 nested query 的真实退栈。
         * @param Request 自有域名、查询类型及原公开对象所有者；整个异步过程保持有效。
         * @return DNS 查询结果；上游失败保留原始错误类别和值。
         */
        [[nodiscard]] static auto ResolveOwned(
            std::shared_ptr<UpstreamState> Owner,
            UpstreamResolveRequest Request) -> Net::awaitable<QueryResult>
        {
            const auto Parsed = Preview::Network::DomainName::Parse(Request.Domain);
            if (!Parsed)
            {
                QueryResult Failed;
                Failed.Error = Parsed.error().Native
                                   ? ResolverFailureFromNative(Parsed.error().Native)
                                   : Parsed.error();
                co_return Failed;
            }
            auto Reservation = Owner->Ids_.TryAcquire();
            if (!Reservation)
            {
                QueryResult Failed;
                Failed.Error = Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable, {}};
                co_return Failed;
            }
            auto Query = std::make_shared<EncodedQuery>(
                *Parsed, QueryParameters{Reservation->Id(), Request.QueryType, 1, 0}, std::move(*Reservation));
            if (!EncodeQuery(*Query))
            {
                QueryResult Failed;
                Failed.Error = Preview::Fault::Failure{Preview::Fault::Code::ProtocolError, {}};
                co_return Failed;
            }

            if (Owner->Servers_.empty())
            {
                QueryResult Failed;
                Failed.Error = Preview::Fault::Failure{Preview::Fault::Code::UnsupportedAddress, {}};
                co_return Failed;
            }
            if (Owner->Mode_ == Mode::Fallback)
            {
                co_return co_await Owner->ResolveFallback(Query);
            }
            if (Owner->Servers_.size() == 1)
            {
                const auto ServerConfig = Owner->Servers_.front();
                co_return co_await Owner->Query_.Query(
                    ServerConfig, Query->Bytes(), Query->Identity);
            }

            if (!Request.FacadeOwner)
            {
                QueryResult Failed;
                Failed.Error = Preview::Fault::Failure{Preview::Fault::Code::NotSupported, {}};
                co_return Failed;
            }
            auto ConcurrentOwner = Owner;
            co_return co_await Owner->ResolveConcurrent(
                std::move(Query), std::move(ConcurrentOwner));
        }
    private:
        /** @brief 一次查询的拥有型 wire、完整问题身份和真实在途 ID 预约；预约覆盖全部传输退栈。 */
        struct EncodedQuery final
        {
            std::array<std::uint8_t, 320> Wire{};
            std::size_t Size{0};
            QueryIdentity Identity;
            QueryIdReservation Reservation;
            EncodedQuery(Preview::Network::DomainName Name, QueryParameters Parameters,
                         QueryIdReservation Lease)
                : Identity(std::move(Name), Parameters), Reservation(std::move(Lease)) {}
            [[nodiscard]] auto Bytes() const noexcept -> std::span<const std::uint8_t>
            {
                return std::span<const std::uint8_t>(Wire).first(Size);
            }
        };
        /** @brief 先用 QueryIdentity 编码标准查询，再追加一份 EDNS0 OPT（1232 字节 UDP 预算）。 */
        [[nodiscard]] static auto EncodeQuery(EncodedQuery &Query) noexcept -> bool
        {
            const auto Encoded = Query.Identity.Encode(std::span<std::uint8_t>(Query.Wire));
            if (!Encoded) return false;
            auto Offset = *Encoded;
            if (Query.Wire.size() - Offset < 11) return false;
            const std::array<std::uint8_t, 11> Opt{0, 0, 0x29, 0x04, 0xD0, 0, 0, 0, 0, 0, 0};
            std::memcpy(Query.Wire.data() + Offset, Opt.data(), Opt.size());
            Offset += Opt.size();
            Query.Wire[10] = 1;
            Query.Size = Offset;
            return true;
        }

        /**
         * @brief 顺序尝试所有上游
         * @param Query 拥有型编码查询；在途 ID 预约随 共享所有者保留至全部 I/O 退栈
         * @return 首个成功结果；全部失败返回最后一个结果
         * @details 每次尝试的绝对 deadline 由 QueryExecutor 内部竞速，
         *          Fallback 不再叠加超时层。
         */
        [[nodiscard]] auto ResolveFallback(std::shared_ptr<EncodedQuery> Query)
            -> Net::awaitable<QueryResult>
        {
            auto QueryFunction = [this](const Server &ServerConfig,
                                        const std::shared_ptr<EncodedQuery> &Value)
                -> Net::awaitable<QueryResult>
            {
                co_return co_await Query_.Query(ServerConfig, Value->Bytes(), Value->Identity);
            };
            co_return co_await Preview::Network::Dns::Detail::ResolveFallback(
                FallbackRequest{Servers_, std::move(Query), std::move(QueryFunction)});
        }

        /**
         * @brief 一次并发查询的完整 owner state。
         * @details results、completion、done、cancel signals、Total/Started 和首个启动异常共同属于
         *          batch；任何退出路径都必须先用该 state 收口已启动 worker。
         */
        template <typename CompletionChannel>
        struct ConcurrentResolveState final
        {
            std::shared_ptr<UpstreamState> Owner;
            Net::any_io_executor Executor;
            std::vector<Server> Servers;
            Mode ModeValue{Mode::Fastest};
            std::shared_ptr<EncodedQuery> Query;
            std::shared_ptr<std::vector<QueryResult>> Results;
            std::shared_ptr<std::vector<std::atomic_bool>> Ready;
            std::shared_ptr<std::atomic<std::size_t>> Completed;
            std::shared_ptr<CompletionChannel> Completion;
            std::shared_ptr<std::vector<std::shared_ptr<Net::cancellation_signal>>> Cancels;
            std::size_t Total{0};
            std::size_t Started{0};
            std::exception_ptr StartFailure;
        };

        /**
         * @brief 一条并发上游查询 worker 的值状态。
         * @details worker frame 只持有 batch owner、server snapshot 和结果槽位索引。
         */
        template <typename CompletionChannel>
        struct ConcurrentQueryJob final
        {
            std::shared_ptr<ConcurrentResolveState<CompletionChannel>> Batch;
            Server ServerConfig;
            std::size_t Index{0};
        };

        /**
         * @brief 执行一条并发上游查询并发布完成通知。
         * @param Job 按值拥有的查询输入、结果槽位和完成 owner。
         * @return worker 完成后返回；单条查询异常转换为该上游的 IoError 结果。
         */
        template <typename CompletionChannel>
        [[nodiscard]] static auto RunQueryJob(ConcurrentQueryJob<CompletionChannel> Job)
            -> Net::awaitable<void>
        {
            const auto Batch = Job.Batch;
            try
            {
                (*Batch->Results)[Job.Index] = co_await Batch->Owner->Query_.Query(
                    Job.ServerConfig, Batch->Query->Bytes(), Batch->Query->Identity);
            }
            catch (...)
            {
                QueryResult Failed;
                Failed.ServerAddr = Job.ServerConfig.Address;
                Failed.Error = Preview::Fault::Failure{Preview::Fault::Code::IoError, {}};
                (*Batch->Results)[Job.Index] = std::move(Failed);
            }
            (*Batch->Ready)[Job.Index].store(true, std::memory_order_release);
            Batch->Completed->fetch_add(1);
            (void)Batch->Completion->try_send(boost::system::error_code{});
        }

        /**
         * @brief 启动 batch 中所有 worker，并记录真实 Started 数量和启动异常。
         * @param Batch 按值拥有 server snapshot、executor 和全部完成 owner 的状态。
         * @return 无；失败只记录，调用者随后统一取消并 join 已启动子集。
         */
        template <typename CompletionChannel>
        static auto StartWorkers(
            const std::shared_ptr<ConcurrentResolveState<CompletionChannel>> &Batch) -> void
        {
            for (std::size_t Index = 0; Index < Batch->Total; ++Index)
            {
                std::shared_ptr<Net::cancellation_signal> Cancel;
                bool Registered = false;
                try
                {
                    const auto ServerConfig = Batch->Servers[Index];
                    Cancel = std::make_shared<Net::cancellation_signal>();
                    Batch->Cancels->push_back(Cancel);
                    Registered = true;
                    auto Job = ConcurrentQueryJob<CompletionChannel>{Batch, ServerConfig, Index};
                    Net::co_spawn(Batch->Executor, RunQueryJob(std::move(Job)),
                                  Net::bind_cancellation_slot(Cancel->slot(), Net::detached));
                    ++Batch->Started;
                }
                catch (...)
                {
                    if (Registered)
                    {
                        Batch->Cancels->pop_back();
                    }
                    if (!Batch->StartFailure)
                    {
                        Batch->StartFailure = std::current_exception();
                    }
                    break;
                }
            }
        }

        /**
         * @brief 对每个已启动 worker 发出取消，并保留首个取消失败。
         * @param Batch 整个并发查询的共享 owner state。
         * @param Failure 已记录的 caller/start 异常；只在为空时记录取消异常。
         * @return 无；每个 signal 都尝试，不因首个异常跳过兄弟 worker。
         */
        template <typename CompletionChannel>
        static auto CancelWorkers(const std::shared_ptr<ConcurrentResolveState<CompletionChannel>> &Batch,
                                  std::exception_ptr &Failure) noexcept -> void
        {
            for (const auto &Signal : *Batch->Cancels)
            {
                try
                {
                    Signal->emit(Net::cancellation_type::all);
                }
                catch (...)
                {
                    if (!Failure)
                    {
                        Failure = std::current_exception();
                    }
                }
            }
        }

        /**
         * @brief 在 caller cancellation 已屏蔽后等待已启动 worker 全部真正收口。
         * @param Batch 整个并发查询的共享 owner state。
         * @return 所有 worker 发出完成通知后返回。
         * @note 只等待 Started，不把未成功 co_spawn 的 worker 伪造为已启动。
         */
        template <typename CompletionChannel>
        [[nodiscard]] static auto JoinWorkers(
            const std::shared_ptr<ConcurrentResolveState<CompletionChannel>> &Batch)
            -> Net::awaitable<void>
        {
            while (Batch->Completed->load() < Batch->Started)
            {
                boost::system::error_code WaitError;
                co_await Batch->Completion->async_receive(
                    Net::redirect_error(Net::use_awaitable, WaitError));
                if (WaitError)
                {
                    throw boost::system::system_error(WaitError);
                }
            }
            co_return;
        }

        /**
         * @brief 并发查询所有上游
         * @details First 在首个成功结果完成时返回；Fastest 等所有任务完成后按
         *          RTT 选择最优结果。取消后等待所有 worker 收尾，确保 owner 生命周期完整。
         * @param Query 拥有型编码查询；在途 ID 预约由 batch 保留到全部 worker 退栈
         * @param Owner 保持 Upstream 与 QueryExecutor 存活的 owner
         * @return 调度后的查询结果
         */
        [[nodiscard]] auto ResolveConcurrent(std::shared_ptr<EncodedQuery> Query,
                                             std::shared_ptr<UpstreamState> Owner)
            -> Net::awaitable<QueryResult>
        {
            const auto Total = Servers_.size();
            using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;
            auto Batch = std::make_shared<ConcurrentResolveState<CompletionChannel>>();
            Batch->Owner = std::move(Owner);
            Batch->Executor = Ex_;
            Batch->Servers = Servers_;
            Batch->ModeValue = Mode_;
            Batch->Query = std::move(Query);
            Batch->Total = Total;
            Batch->Results = std::make_shared<std::vector<QueryResult>>(Total);
            Batch->Ready = std::make_shared<std::vector<std::atomic_bool>>(Total);
            for (auto &Ready : *Batch->Ready)
            {
                Ready.store(false, std::memory_order_relaxed);
            }
            Batch->Completed = std::make_shared<std::atomic<std::size_t>>(0);
            Batch->Completion = std::make_shared<CompletionChannel>(Ex_, 1);
            Batch->Cancels =
                std::make_shared<std::vector<std::shared_ptr<Net::cancellation_signal>>>();
            Batch->Cancels->reserve(Total);
            StartWorkers(Batch);

            std::exception_ptr Failure = Batch->StartFailure;
            bool HasWinner = false;
            std::size_t WinnerIndex = 0;
            if (!Failure)
            {
                try
                {
                    while (true)
                    {
                        boost::system::error_code WaitError;
                        co_await Batch->Completion->async_receive(
                            Net::redirect_error(Net::use_awaitable, WaitError));
                        if (WaitError)
                        {
                            Failure = std::make_exception_ptr(
                                boost::system::system_error(WaitError));
                            break;
                        }
                        if (Batch->ModeValue == Mode::First)
                        {
                            for (std::size_t Index = 0; Index < Batch->Started; ++Index)
                            {
                                if (!(*Batch->Ready)[Index].load(std::memory_order_acquire))
                                {
                                    continue;
                                }
                                const auto &Result = (*Batch->Results)[Index];
                                if (Result.Error.Succeeded() && !Result.Response.Ips.Empty())
                                {
                                    HasWinner = true;
                                    WinnerIndex = Index;
                                    break;
                                }
                            }
                            if (HasWinner)
                            {
                                break;
                            }
                        }
                        if (Batch->Completed->load() >= Batch->Started)
                        {
                            break;
                        }
                    }
                }
                catch (...)
                {
                    Failure = std::current_exception();
                }
            }

            if (Failure || HasWinner)
            {
                CancelWorkers(Batch, Failure);
                try
                {
                    co_await Net::this_coro::reset_cancellation_state(
                        Net::disable_cancellation());
                }
                catch (...)
                {
                    if (!Failure)
                    {
                        Failure = std::current_exception();
                    }
                }
                co_await JoinWorkers(Batch);
            }

            if (Failure)
            {
                std::rethrow_exception(Failure);
            }
            if (HasWinner)
            {
                co_return std::move((*Batch->Results)[WinnerIndex]);
            }
            co_return SelectBest(*Batch->Results);
        }

        Net::any_io_executor Ex_;
        std::vector<Server> Servers_;
        Mode Mode_;
        QueryExecutor Query_;
        QueryIds Ids_{4096};
    };

} // namespace Preview::Network::Dns::Detail
