/** @file Connector.hpp @brief Asio唯一ABI适配；拥有描述符、关联属性和一次有界scatter缓冲。 */
#pragma once
#include <tuple>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>
#include <array>
#include <algorithm>
#include <cstddef>
#include <span>
#include <utility>
namespace Prism::Transport
{
    /**
     * @brief Asio 官方 ABI 的唯一适配层，把 typed 前门转换成 error_code/bytes 完成签名。
     * @details 输入所有权：构造与赋值移交 SharedTransmission 的共享所有权，每个异步操作再把该 shared_ptr
     *          复制进操作帧，因此载体一定保活到 completion；Buffers 序列只借用到该操作 completion——单缓冲
     *          读直接写入调用方缓冲区，多缓冲读经操作帧自有的 64KiB 栈上 scratch 复制一次，写侧逐缓冲区
     *          调用 WriteExact，故整段序列在 completion 前不得改写或释放。Release() 把所有权整体移出。
     *          输出与错误：ABI 完成只带 (error_code, size)，不另建第二份错误事实，只在最终返回处经
     *          Detail::ToAsioFailure 转换；Native 存在时保持原 category/value，无 Native 时把 EOF、取消、
     *          超时分别映射为 asio::error::eof/operation_aborted/timed_out，供 TLS engine 等官方消费者识别。
     *          底层 typed 的取消、EOF、本地封止与原生错误四类在转换前各自保留 Code 与 Native。
     *          取消：本类型不暴露 Cancel/Close 门面，取消只能来自底层 Transmission::Cancel 或 handler 的
     *          关联 cancellation slot；每次操作先 post 回载体 executor，再由 ConfigureIo 检出已发生的取消，
     *          交付一次 Canceled。
     *          半关闭与最终关闭者：Connector 不提供 WriteShutdown，写半关闭必须走 lowest_layer()/底层前门；
     *          本类型只 pin 载体，裸描述符的最终关闭者仍是底层 Transmission 叶子，Close 由该层执行。
     *          executor：get_executor()/操作 executor 固定为 Trans_->Executor()，即载体冷构造时的原域；
     *          完成投递在 handler 的关联 executor 上，要求单一执行域装配。
     * @note 未定义：Release() 之后本对象不保留任何所有权，后续调用会解引用空 shared_ptr，当前代码没有
     *       防御路径；「Release 即终态」是契约要求而非实现保证，留待 M13 决定处置方式。
     */
    class Connector final
    {
    public:
        using ExecutorType = Net::any_io_executor;
        using executor_type = ExecutorType;
        using TransmissionPtr = Prism::SharedTransmission;
        using lowest_layer_type = Prism::Transmission;
        using LowestLayerType = Connector;
        explicit Connector(TransmissionPtr Carrier) : Trans_(std::move(Carrier)) {}
        Connector(Connector&&) noexcept = default;
        auto operator=(Connector&&) noexcept -> Connector& = default;
        [[nodiscard]] auto get_executor() const -> ExecutorType { return Trans_->Executor(); }
        [[nodiscard]] auto Executor() const -> ExecutorType { return get_executor(); }
        [[nodiscard]] auto lowest_layer() noexcept -> Prism::Transmission& { return *Trans_; }
        [[nodiscard]] auto lowest_layer() const noexcept -> const Prism::Transmission& { return *Trans_; }
        [[nodiscard]] auto LowestLayer() noexcept -> Connector& { return *this; }
        [[nodiscard]] auto LowestLayer() const noexcept -> const Connector& { return *this; }
        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission* { return Trans_.get(); }
        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission* { return Trans_.get(); }
        [[nodiscard]] auto Transmission() const -> Prism::Transmission& { return *Trans_; }
        [[nodiscard]] auto Release() -> TransmissionPtr { return std::move(Trans_); }
        /** @brief ABI方法不另建错误事实；只在最终返回时把IoResult转换成Asio签名。 */
        template<class Buffers, class Token>
        auto async_read_some(const Buffers& Sequence, Token&& Handler)
        {
            return Net::async_initiate<Token, void(boost::system::error_code, std::size_t)>(
                Net::co_composed<void(boost::system::error_code, std::size_t)>(ReadOperation{}, Executor()),
                Handler, Input<Buffers>{Trans_, Sequence});
        }
        template<class Buffers, class Token>
        auto async_write_some(const Buffers& Sequence, Token&& Handler)
        {
            return Net::async_initiate<Token, void(boost::system::error_code, std::size_t)>(
                Net::co_composed<void(boost::system::error_code, std::size_t)>(WriteOperation{}, Executor()),
                Handler, Input<Buffers>{Trans_, Sequence});
        }
        [[nodiscard]] auto ReadExact(std::span<std::byte> Buffer) -> Net::awaitable<IoResult>
        { return Trans_->ReadExact(Buffer); }
        [[nodiscard]] auto WriteExact(std::span<const std::byte> Buffer) -> Net::awaitable<IoResult>
        { return Trans_->WriteExact(Buffer); }
    private:
        template<class Buffers>
        struct Input final { TransmissionPtr Carrier; Buffers Sequence; };
        struct ReadOperation final
        {
            template<class State, class Buffers>
            auto operator()(State Operation, Input<Buffers> Request) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                co_await Net::post(Request.Carrier->Executor(), Net::deferred);
                const auto Size = Net::buffer_size(Request.Sequence);
                if (Size == 0) co_return std::tuple{boost::system::error_code{}, std::size_t{0}};
                auto Begin = Net::buffer_sequence_begin(Request.Sequence);
                const auto End = Net::buffer_sequence_end(Request.Sequence);
                auto Next = Begin;
                ++Next;
                IoResult Result;
                if (Next == End)
                {
                    const Net::mutable_buffer Buffer(*Begin);
                    Result = co_await Request.Carrier->ReadSome(
                        std::span<std::byte>(static_cast<std::byte*>(Buffer.data()), Buffer.size()), Net::deferred);
                }
                else
                {
                    std::array<std::byte, 64U * 1024U> Scratch;
                    const auto Capacity = (std::min)(Size, Scratch.size());
                    Result = co_await Request.Carrier->ReadSome(std::span(Scratch).first(Capacity), Net::deferred);
                    if (Result.Bytes > Capacity) co_return std::tuple{Detail::ToAsioFailure({Fault::Code::InvalidArgument}), std::size_t{0}};
                    if (Result.Bytes != 0) Net::buffer_copy(Request.Sequence, Net::buffer(Scratch.data(), Result.Bytes));
                }
                co_return std::tuple{Detail::ToAsioFailure(Result.Failure), Result.Bytes};
            }
        };
        struct WriteOperation final
        {
            template<class State, class Buffers>
            auto operator()(State Operation, Input<Buffers> Request) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                co_await Net::post(Request.Carrier->Executor(), Net::deferred);
                IoResult Result;
                for (auto It = Net::buffer_sequence_begin(Request.Sequence), End = Net::buffer_sequence_end(Request.Sequence);
                     It != End; ++It)
                {
                    const Net::const_buffer Buffer(*It);
                    auto Part = co_await Request.Carrier->WriteExact(
                        std::span<const std::byte>(static_cast<const std::byte*>(Buffer.data()), Buffer.size()), Net::deferred);
                    Result.Bytes += Part.Bytes;
                    Result.Failure = Part.Failure;
                    if (Result.Failure.Failed()) break;
                }
                co_return std::tuple{Detail::ToAsioFailure(Result.Failure), Result.Bytes};
            }
        };
        TransmissionPtr Trans_;
    };
}
