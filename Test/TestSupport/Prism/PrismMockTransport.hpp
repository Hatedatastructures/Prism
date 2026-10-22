/** @file PrismMockTransport.hpp @brief 保留原注入行为、真实值 I/O 与 peer EOF 的传输 fixture。 */
#pragma once
#include <Prism/Foundation/Error.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/as_tuple.hpp>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism
{
    namespace net = boost::asio;
    /** @brief 仅测试编排使用；状态在原 executor，正式基类预约保活到 completion 返回。 */
    class PrismMockTransport final : public Transmission
    {
    public:
        explicit PrismMockTransport(net::any_io_executor Executor)
            : Transmission(Executor), Ex_(std::move(Executor)), Events_(Ex_, 1) {}
        [[nodiscard]] auto Executor() const -> net::any_io_executor override { return Ex_; }
        [[nodiscard]] auto IsOpen() const noexcept -> bool override { return !Closed_; }
        [[nodiscard]] auto TransportType() const noexcept -> Type override { return TransportKind; }
        /** @brief 注入 peer 写半关闭，保留本端发送；与正式 WriteShutdown 的方向不同。 */
        auto InjectPeerEof() -> void { PeerEof_ = true; Notify(); }
        [[nodiscard]] auto PeerEof() const noexcept -> bool { return PeerEof_; }
        auto InjectRead(std::vector<std::uint8_t> Data) -> void
        { ToRead.insert(ToRead.end(), Data.begin(), Data.end()); Notify(); }
        /** @brief 令前缀排空后的下一次读取交付终态，并在其后保持粘滞。 */
        auto DeliverReadTerminal(std::error_code Error) -> void
        { DeliverError_ = Error; Notify(); }
        /** @brief 精确保存外部注入的 category/value，包括同次 partial 字节。 */
        auto SetReadError(std::error_code Error) -> void { ReadError_ = Error; Notify(); }
        auto SetWriteError(std::error_code Error) -> void { WriteError_ = Error; }
        [[nodiscard]] auto IsClosed() const noexcept -> bool { return Closed_; }
        [[nodiscard]] auto IsCancelled() const noexcept -> bool { return Cancelled_; }
        /// 读取字节流（由测试初始化；耗尽后等待事件）
        std::vector<std::uint8_t> ToRead;
        /// 捕获的全部写入数据
        std::vector<std::uint8_t> Written;
        /// 单次读取后自动复位（注入单点读取错误）
        bool FailNextRead{false};
        /// 单次写入后自动复位（注入单点写入错误）
        bool FailNextWrite{false};
        /// 第 N 次读取返回 io_error（1 起；SIZE_MAX = 禁用）
        std::size_t ReadFailAt{std::numeric_limits<std::size_t>::max()};
        /// 第 N 次写入返回 io_error（1 起；SIZE_MAX = 禁用）
        std::size_t WriteFailAt{std::numeric_limits<std::size_t>::max()};
        /// 单次写入返回字节数上限（0 = 不限制；>0 模拟半包写）
        std::size_t MaxWrite{0};
        /// 单次读取返回字节数上限（0 = 不限制；>0 模拟真实短读）
        std::size_t MaxRead{0};
        /// 按调用次序变化的写入上限（非空时覆盖 MaxWrite，0 = 不限制）
        std::vector<std::size_t> WriteLimitSequence;
        /// 写入返回 0 且不设置错误（用于验证完整写入层的 zero-progress 处理）
        bool ZeroWrite{false};
        /// 写入返回超过请求长度（用于验证完整写入层的防御性检查）
        bool OverreportWrite{false};
        /// 读取返回超过请求长度（用于验证协议层的防御性检查）
        bool OverreportRead{false};
        /// 下一次读取返回错误时一并报告的有效字节数
        std::size_t ReadErrorBytes{0};
        /// 下一次写入返回错误时一并报告的有效字节数
        std::size_t WriteErrorBytes{0};
        /// 底层传输类型（Dgram 测试设为 Udp，默认 Tcp）
        Type TransportKind{Type::Tcp};
        /// 有限注入流耗尽后返回 EOF；false 时空读事件驱动等待
        bool EofOnDrain{false};
        /// 已执行读取次数
        std::size_t ReadsDone{0};
        /// 已执行写入次数
        std::size_t WritesDone{0};


    protected:
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            net::async_initiate<Completion, void(IoResult)>(
                net::co_composed<void(IoResult)>(ReadOperation{}, Ex_), Handler,
                ReadInput{std::static_pointer_cast<PrismMockTransport>(weak_from_this().lock()), Buffer});
        }
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        { Transmission::PostResult(Ex_, std::move(Handler), Write(Buffer)); }
        auto StartWriteShutdown(Completion Handler) -> void override
        { WriteClosed_ = true; Transmission::PostResult(Ex_, std::move(Handler), {}); }
        [[nodiscard]] auto OnClose() -> ControlResult override { Closed_ = true; Notify(); return {}; }
        [[nodiscard]] auto OnCancel() -> ControlResult override { Cancelled_ = true; Notify(); return {}; }
    private:
        struct ReadInput final { std::shared_ptr<PrismMockTransport> Owner; std::span<std::byte> Buffer; };
        struct ReadOperation final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Transmission::ConfigureIo(Operation);
                ++Input.Owner->ReadsDone;
                for (;;)
                {
                    if (!!Operation.cancelled()) co_return std::tuple{IoResult{0, {Fault::Code::Canceled}}};
                    if (auto Result = Input.Owner->TryRead(Input.Buffer)) co_return std::tuple{*Result};
                    const auto [Error] = co_await Input.Owner->Events_.async_receive(net::as_tuple(net::deferred));
                    if (Error) co_return std::tuple{IoResult{0, Fault::FromNative(static_cast<std::error_code>(Error))}};
                }
            }
        };
        [[nodiscard]] auto TryRead(std::span<std::byte> Buffer) -> std::optional<IoResult>
        {
            if (ReadTerminal_)
            {
                return IoResult{0, *ReadTerminal_};
            }
            if (FailNextRead || ReadsDone == ReadFailAt)
            { FailNextRead = false; return IoResult{0, {Fault::Code::IoError}}; }
            if (Closed_) return IoResult{0, {Fault::Code::Eof}};
            if (Cancelled_)
            { Cancelled_ = false; return IoResult{0, {Fault::Code::Canceled}}; }
            if (DeliverError_ && ReadPos_ >= ToRead.size())
            {
                const auto Failure = Fault::FromNative(*DeliverError_);
                DeliverError_.reset();
                ReadTerminal_ = Failure;
                return IoResult{0, Failure};
            }
            if (ReadError_)
            {
                const auto Count = (std::min)(ReadErrorBytes, Buffer.size());
                const auto Available = (std::min)(Count, ToRead.size() - ReadPos_);
                if (Available != 0) std::memcpy(Buffer.data(), ToRead.data() + ReadPos_, Available);
                ReadPos_ += Available;
                const auto Failure = Fault::FromNative(*ReadError_);
                ReadError_.reset();
                return IoResult{Available, Failure};
            }
            if (PeerEof_) return IoResult{0, {Fault::Code::Eof}};
            if (OverreportRead) return IoResult{Buffer.size() + 1, {}};
            if (ReadPos_ < ToRead.size())
            {
                auto Count = (std::min)(Buffer.size(), ToRead.size() - ReadPos_);
                if (MaxRead != 0)
                    Count = (std::min)(Count, MaxRead);
                if (Count != 0) std::memcpy(Buffer.data(), ToRead.data() + ReadPos_, Count);
                ReadPos_ += Count;
                if (DeliverError_ && ReadPos_ >= ToRead.size())
                {
                    ReadTerminal_ = Fault::FromNative(*DeliverError_);
                    DeliverError_.reset();
                }
                return IoResult{Count, {}};
            }
            if (EofOnDrain) return IoResult{0, {Fault::Code::Eof}};
            return std::nullopt;
        }
        [[nodiscard]] auto Write(std::span<const std::byte> Buffer) -> IoResult
        {
            if (WriteError_)
            {
                const auto Count = (std::min)(WriteErrorBytes, Buffer.size());
                const auto* Source = reinterpret_cast<const std::uint8_t*>(Buffer.data());
                Written.insert(Written.end(), Source, Source + Count);
                const auto Failure = Fault::FromNative(*WriteError_);
                WriteError_.reset();
                return {Count, Failure};
            }
            ++WritesDone;
            if (FailNextWrite || WritesDone == WriteFailAt || Closed_ || WriteClosed_)
            { FailNextWrite = false; return {0, {Fault::Code::IoError}}; }
            if (OverreportWrite) return {Buffer.size() + 1, {}};
            if (ZeroWrite) return {};
            auto Limit = MaxWrite;
            if (!WriteLimitSequence.empty()) Limit = WriteLimitSequence[(WritesDone - 1) % WriteLimitSequence.size()];
            auto Count = Buffer.size();
            if (Limit != 0) Count = (std::min)(Buffer.size(), Limit);
            const auto* Source = reinterpret_cast<const std::uint8_t*>(Buffer.data());
            Written.insert(Written.end(), Source, Source + Count);
            return {Count, {}};
        }
        auto Notify() -> void { (void)Events_.try_send(boost::system::error_code{}); }
        net::any_io_executor Ex_;
        net::experimental::channel<void(boost::system::error_code)> Events_;
        std::size_t ReadPos_{0};
        bool Closed_{false}, PeerEof_{false}, WriteClosed_{false}, Cancelled_{false};
        std::optional<std::error_code> ReadError_, WriteError_;
        std::optional<std::error_code> DeliverError_;
        std::optional<Fault::Failure> ReadTerminal_;
    };

} // namespace Prism
