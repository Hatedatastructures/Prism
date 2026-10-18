/** @file MemoryStream.hpp @brief 同一strand上的有界内存流，统一IoResult和真实等待操作。 */
#pragma once
#include <tuple>
#include <Prism/Transport/Stream.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/as_tuple.hpp>
#include <cstring>
#include <optional>
#include <array>
namespace Prism
{
    /**
     * @brief 合成测试与基准用的有界内存流载体，成对端点在同一 strand 上互写有界队列。
     * @details 输入所有权：每个端点独占拥有自己的 State（shared_ptr），peer 只以 weak_ptr 引用；读写 span
     *          都只借用到该操作 completion，因为写在本端原域将字节复制进 peer 池的 OwnedBytes 租约、读把本地
     *          队首块复制到用户 buffer 后归还租约并唤醒 peer 的可写信号。每端 64 个 64KiB 块由自己的池发放，
     *          队列节点与租约一一对应，缩短逻辑长度不提前归还额度。
     *          输出与错误：唯一事实是 IoResult{Bytes, Failure}。本端已 Close 或本操作被取消交付 Canceled，
     *          对端半关闭交付 Eof，本端已 WriteShutdown 或 peer 已 Closed 交付 ConnectionAborted，后三类的
     *          Native 一律为空；只有真实 channel/timer 返回的原生错误才进入 Native。计时器正常到期
     *          返回 Timeout，其取消竞争读取产生的 operation_aborted 不是超时首因，不填入 Native。
     *          写方向队列满时等待 peer 腾空而不报 WouldBlock。
     *          取消：OnCancel 递增 CancelEpoch 并同时唤醒本端与 peer，在途的读/写循环在下一个检查点恰好交付
     *          一次 {0, Canceled}；可重复调用，取消不销毁已排队的块。
     *          半关闭：StartWriteShutdown 置本端 WriteClosed（后续写 ConnectionAborted）并置 peer 的 PeerEof
     *          （peer 读 Eof），本端读取方向完全保持可用；半关闭不关闭 State，也不关闭 peer。
     *          最终关闭者：OnClose 是唯一本层终态动作（置 Closed 并让 peer 见 EOF），没有裸描述符需要关闭；
     *          块与队列的物理释放由两端 shared_ptr 归零决定，peer 端已排队块的释放顺序不由本端 Close 规定。
     *          executor：State::Executor 是构造时 make_strand 得到的唯一域，MakeMemoryPair 让两端共享同一
     *          strand；Head/Tail/Count/Offset/PeerEof/WriteClosed/CancelEpoch/Timeout 为非原子成员，只能在
     *          该 strand 上变更，要求单一执行域，跨 strand 配对不受支持（私有构造仅友元 MakeMemoryPair）。
     * @note 未定义：本载体不参与真实网络，Close/Drain 与 Executor 的原域语义沿用 Transmission；SetTimeout
     *       只覆盖读方向，写方向的无界等待没有规定上界，留待 M13 决定。
     */
    class MemoryStream final : public Transmission
    {
    public:
        static constexpr std::chrono::milliseconds DefaultTimeout{0};
        /** @brief 成对端点共享一个strand，各自拥有64个64KiB块；取消/半关不销毁在途块。 */
        struct State final
        {
            explicit State(ExecutorType Executor)
                : Executor(std::move(Executor)), Readable(this->Executor, 1), Writable(this->Executor, 1),
                  Pool(Memory::BytePoolOptions{64U * 1024U, 64}) {}
            ExecutorType Executor;
            Net::experimental::channel<void(boost::system::error_code)> Readable, Writable;
            Memory::BytePool Pool;
            std::array<std::optional<Memory::OwnedBytes>, 64> Queue;
            std::size_t Head{0}, Tail{0}, Count{0}, Offset{0};
            std::uint64_t CancelEpoch{0};
            std::atomic<bool> Closed{false};
            bool PeerEof{false}, WriteClosed{false};
            std::chrono::milliseconds Timeout{DefaultTimeout};
        };
        explicit MemoryStream(ExecutorType Executor)
            : MemoryStream(std::make_shared<State>(Net::make_strand(std::move(Executor))), {}) {}
        [[nodiscard]] auto IsOpen() const -> bool override { return !In_->Closed.load(); }
        auto SetTimeout(std::chrono::milliseconds Timeout) -> void override { In_->Timeout = Timeout; }
    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Completion Routed(Transport::Detail::OriginalCompletion(Executor(), std::move(Handler)));
            Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(ReadOperation{}, Executor()),
                Routed, ReadInput{In_, Buffer});
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Completion Routed(Transport::Detail::OriginalCompletion(Executor(), std::move(Handler)));
            Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(WriteOperation{}, Executor()),
                Routed, WriteInput{In_, Peer_.lock(), Buffer});
        }
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            In_->WriteClosed = true;
            if (auto Peer = Peer_.lock()) { Peer->PeerEof = true; Notify(Peer); }
            Transport::Detail::PostResult(Executor(), std::move(Handler), {});
        }
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            In_->Closed.store(true);
            In_->WriteClosed = true;
            Notify(In_);
            if (auto Peer = Peer_.lock()) { Peer->PeerEof = true; Notify(Peer); }
            return {};
        }
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            ++In_->CancelEpoch;
            Notify(In_);
            if (auto Peer = Peer_.lock()) Notify(Peer);
            return {};
        }
    private:
        struct ReadInput final { std::shared_ptr<State> In; std::span<std::byte> Buffer; };
        struct WriteInput final { std::shared_ptr<State> In, Peer; std::span<const std::byte> Buffer; };
        static auto Notify(const std::shared_ptr<State>& Value) -> void
        { (void)Value->Readable.try_send(boost::system::error_code{}); (void)Value->Writable.try_send(boost::system::error_code{}); }
        [[nodiscard]] static auto Failure(boost::system::error_code Error) -> IoResult
        { return {0, Fault::FromNative(static_cast<std::error_code>(Error))}; }
        struct ReadOperation final
        {
            template<class OperationState>
            auto operator()(OperationState Operation, ReadInput Input) const -> void
            {
                Transport::Detail::ConfigureIo(Operation);
                const auto Epoch = Input.In->CancelEpoch;
                Net::steady_timer Timer(Input.In->Executor);
                if (Input.In->Timeout.count() > 0) Timer.expires_after(Input.In->Timeout);
                else Timer.expires_at((Net::steady_timer::time_point::max)());
                while (true)
                {
                    if (Input.In->Closed.load()) co_return std::tuple{IoResult{0, {Fault::Code::Canceled}}};
                    if (Input.In->CancelEpoch != Epoch || !!Operation.cancelled()) co_return std::tuple{IoResult{0, {Fault::Code::Canceled}}};
                    if (Input.Buffer.empty()) co_return std::tuple{IoResult{}};
                    if (Input.In->Count != 0)
                    {
                        auto& Bytes = *Input.In->Queue[Input.In->Head];
                        const auto Count = (std::min)(Input.Buffer.size(), Bytes.Size() - Input.In->Offset);
                        std::memcpy(Input.Buffer.data(), Bytes.Bytes().data() + Input.In->Offset, Count);
                        Input.In->Offset += Count;
                        if (Input.In->Offset == Bytes.Size())
                        {
                            Input.In->Queue[Input.In->Head].reset();
                            Input.In->Head = (Input.In->Head + 1) % Input.In->Queue.size();
                            --Input.In->Count;
                            Input.In->Offset = 0;
                            (void)Input.In->Writable.try_send(boost::system::error_code{});
                        }
                        co_return std::tuple{IoResult{Count, {}}};
                    }
                    if (Input.In->PeerEof) co_return std::tuple{IoResult{0, {Fault::Code::Eof}}};
                    auto [Order, Error, TimerError] = co_await Net::experimental::make_parallel_group(
                        Input.In->Readable.async_receive(Net::deferred), Timer.async_wait(Net::deferred))
                        .async_wait(Net::experimental::wait_for_one(), Net::deferred);
                    if (Order[0] == 1 && !TimerError)
                    { co_return std::tuple{IoResult{0, {Fault::Code::Timeout}}}; }
                    if (Error) co_return std::tuple{Failure(Error)};
                }
            }
        };
        struct WriteOperation final
        {
            template<class OperationState>
            auto operator()(OperationState Operation, WriteInput Input) const -> void
            {
                Transport::Detail::ConfigureIo(Operation);
                const auto Epoch = Input.In->CancelEpoch;
                while (true)
                {
                    if (!Input.Peer || Input.In->Closed.load() || Input.In->WriteClosed || Input.Peer->Closed.load())
                        co_return std::tuple{IoResult{0, {Fault::Code::ConnectionAborted}}};
                    if (Input.In->CancelEpoch != Epoch || !!Operation.cancelled()) co_return std::tuple{IoResult{0, {Fault::Code::Canceled}}};
                    if (Input.Buffer.empty()) co_return std::tuple{IoResult{}};
                    if (Input.Peer->Count < Input.Peer->Queue.size()) break;
                    auto [Error] = co_await Input.Peer->Writable.async_receive(Net::as_tuple(Net::deferred));
                    if (Error) co_return std::tuple{Failure(Error)};
                }
                const auto Count = (std::min)(Input.Buffer.size(), Input.Peer->Pool.BlockSize());
                auto Bytes = Input.Peer->Pool.TryAcquire(Count);
                if (!Bytes) co_return std::tuple{IoResult{0, Bytes.error()}};
                std::memcpy(Bytes->WritableBytes().data(), Input.Buffer.data(), Count);
                Input.Peer->Queue[Input.Peer->Tail].emplace(std::move(*Bytes));
                Input.Peer->Tail = (Input.Peer->Tail + 1) % Input.Peer->Queue.size();
                ++Input.Peer->Count;
                (void)Input.Peer->Readable.try_send(boost::system::error_code{});
                co_return std::tuple{IoResult{Count, {}}};
            }
        };
        MemoryStream(std::shared_ptr<State> Input, std::weak_ptr<State> Peer)
            : Transmission(Input->Executor), In_(std::move(Input)), Peer_(std::move(Peer)) {}
        std::shared_ptr<State> In_;
        std::weak_ptr<State> Peer_;
        friend auto MakeMemoryPair(ExecutorType) -> std::pair<MemoryStream, MemoryStream>;
    };
    [[nodiscard]] inline auto MakeMemoryPair(Net::any_io_executor Executor) -> std::pair<MemoryStream, MemoryStream>
    {
        const auto Domain = Net::make_strand(std::move(Executor));
        auto First = std::make_shared<MemoryStream::State>(Domain);
        auto Second = std::make_shared<MemoryStream::State>(Domain);
        return {MemoryStream(First, Second), MemoryStream(Second, First)};
    }
    static_assert(Stream<MemoryStream>);
}
