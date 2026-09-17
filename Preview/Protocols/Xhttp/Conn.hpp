/**
 * @file Conn.hpp
 * @brief XHTTP 方案连接装饰器（Stream-one：TLS + h2 + 单 POST 双向流）
 * @details 服务端流程：
 *          1. 底层传输执行 TLS 服务端握手（Encrypted::SslHandshake）
 *          2. 建立 h2 会话（SessionImpl），处理 SETTINGS/PING
 *          3. 匹配 POST {Path} 请求 → 响应 200
 *          4. 返回双向流传输：读 = h2 DATA 帧载荷，写 = h2 DATA 帧
 * @note 依赖 core/http2 自包含实现（T2-6）
 */

#pragma once

#include <Preview/Foundation/Utility/Diagnose/Log.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Http2/Impl.hpp>
#include <Preview/Protocols/Http2/Session.hpp>
#include <Preview/Foundation/Memory/Container.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Transport/Encrypted.hpp>
#include <Preview/Protocols/Xhttp/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/ssl.h>

#include <array>
#include <atomic>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <memory>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace Preview::Xhttp
{

    namespace Net = boost::asio;
    namespace h2 = Preview::Http2;

    /// h2 会话共享指针
    using SharedH2Session = std::shared_ptr<h2::SessionImpl>;

    using boost::asio::experimental::awaitable_operators::operator||;

    /**
     * @class WireWriter
     * @brief XHTTP 底层字节串行写入器
     * @details driver、响应头和数据回调共享一个实例，所有写入先排队，
     *          sink 通过 Transmission::AsyncWrite 完整消费字节。
     */
    class WireWriter final : public std::enable_shared_from_this<WireWriter>
    {
    public:
        using Sink = std::function<Net::awaitable<void>(std::span<const std::byte>)>;

        WireWriter(Net::any_io_executor Executor, Sink SinkFunction)
            : Ex_(std::move(Executor)), Sink_(std::move(SinkFunction))
        {
        }

        WireWriter(const WireWriter &) = delete;
        auto operator=(const WireWriter &) -> WireWriter & = delete;

        [[nodiscard]] auto Write(std::span<const std::byte> Data) -> Net::awaitable<void>
        {
            if (Data.empty())
            {
                co_return;
            }
            if (Closed_ || !Sink_)
            {
                throw std::system_error(std::make_error_code(std::errc::not_connected));
            }

            auto Request = std::make_shared<RequestState>(Ex_, Data);
            Queue_.push_back(Request);
            Start();

            boost::system::error_code WaitEc;
            const auto Failed = co_await Request->Done.async_receive(
                Net::redirect_error(Net::use_awaitable, WaitEc));
            if (WaitEc || Failed != 0)
            {
                int Value = static_cast<int>(std::errc::io_error);
                if (WaitEc)
                {
                    Value = WaitEc.value();
                }
                throw std::system_error(Value, std::system_category());
            }
        }

        void Close()
        {
            Closed_ = true;
            FailQueued(boost::system::errc::make_error_code(boost::system::errc::not_connected));
        }

    private:
        using Completion = Net::experimental::channel<void(boost::system::error_code, int)>;

        struct RequestState
        {
            RequestState(Net::any_io_executor Executor, std::span<const std::byte> Data)
                : Data(Data.begin(), Data.end()), Done(Executor, 1)
            {
            }

            std::vector<std::byte> Data;
            Completion Done;
        };

        void Start()
        {
            if (WriterRunning_ || Closed_ || Queue_.empty())
            {
                return;
            }
            WriterRunning_ = true;
            auto Self = shared_from_this();
            Net::co_spawn(Ex_, [Self]() -> Net::awaitable<void> { co_await Self->Loop(); }, Net::detached);
        }

        void FailQueued(boost::system::error_code Ec)
        {
            while (!Queue_.empty())
            {
                auto Request = std::move(Queue_.front());
                Queue_.pop_front();
                int Failed = 0;
                if (Ec)
                {
                    Failed = 1;
                }
                (void)Request->Done.try_send(Ec, Failed);
            }
        }

        [[nodiscard]] auto IoError() const -> boost::system::error_code
        {
            return boost::system::errc::make_error_code(boost::system::errc::io_error);
        }

        auto Loop() -> Net::awaitable<void>
        {
            while (!Queue_.empty())
            {
                auto Request = std::move(Queue_.front());
                Queue_.pop_front();
                boost::system::error_code Ec;
                try
                {
                    if (Closed_ || !Sink_)
                    {
                        Ec = boost::system::errc::make_error_code(boost::system::errc::not_connected);
                    }
                    else
                    {
                        co_await Sink_(Request->Data);
                    }
                }
                catch (...)
                {
                    Ec = IoError();
                }

                int Failed = 0;
                if (Ec)
                {
                    Failed = 1;
                }
                (void)Request->Done.try_send(Ec, Failed);
                if (Ec)
                {
                    Closed_ = true;
                    FailQueued(Ec);
                    break;
                }
            }
            WriterRunning_ = false;
            co_return;
        }

        Net::any_io_executor Ex_;
        Sink Sink_;
        std::deque<std::shared_ptr<RequestState>> Queue_;
        bool WriterRunning_{false};
        bool Closed_{false};
    };

    /**
     * @class XhttpTransport
     * @brief XHTTP 双向流传输（Transmission 装饰器）
     * @details 读 = 会话 DATA 帧投递队列；写 = 经会话提交 DATA 帧。
     *          匹配的流 ID 在 POST 到达前为 -1（写缓冲至匹配后 flush）。
     */
    class XhttpTransport final : public Transmission
    {
    public:
        /**
         * @brief 写回调（提交 DATA 帧到会话）
         * @param StreamId 目标流
         * @param Data 载荷
         */
        using WriteCb = std::function<Net::awaitable<void>(std::int32_t StreamId,
                                                             std::span<const std::byte>)>;

        /// 请求方向半关闭回调（发送空 DATA + END_STREAM）
        using FinishCb = std::function<Net::awaitable<void>(std::int32_t StreamId)>;

        /**
         * @brief 构造
         * @param Executor 执行器
         * @param WriteFn 写回调（提交 DATA 帧）
         */
        explicit XhttpTransport(
            Net::any_io_executor Executor,
            WriteCb WriteFn,
            FinishCb FinishFn = {})
            : Ex_(std::move(Executor)),
              WriteFn_(std::move(WriteFn)),
              FinishFn_(std::move(FinishFn)),
              Notify_(Ex_, 64)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (Buffer.empty())
            {
                ErrorCode.clear();
                co_return 0;
            }
            while (RxOffset_ >= RxCurrent_.size())
            {
                if (Closed_)
                {
                    ErrorCode = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Eof_)
                {
                    ErrorCode = make_error_code(Error::UnexpectedEof);
                    co_return 0;
                }
                if (EofPending_ && !Notify_.ready())
                {
                    EofPending_ = false;
                    Eof_ = true;
                    ErrorCode.clear();
                    co_return 0;
                }
                boost::system::error_code ChEc;
                auto Block = co_await Notify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, ChEc));
                if (ChEc)
                {
                    ErrorCode = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Block.empty())
                {
                    Eof_ = true;
                    ErrorCode.clear();
                    co_return 0;
                }
                RxCurrent_ = std::move(Block);
                RxOffset_ = 0;
            }
            const auto N = std::min(Buffer.size(), RxCurrent_.size() - RxOffset_);
            std::memcpy(Buffer.data(), RxCurrent_.data() + RxOffset_, N);
            RxOffset_ += N;
            ErrorCode.clear();
            co_return N;
        }

        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (Buffer.empty())
            {
                ErrorCode.clear();
                co_return 0;
            }
            if (Closed_ || Finished_ || !WriteFn_)
            {
                ErrorCode = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (StreamId_ < 0)
            {
                // 流未匹配：缓冲写
                WritePending_.insert(WritePending_.end(), Buffer.begin(), Buffer.end());
                ErrorCode.clear();
                co_return Buffer.size();
            }

            auto Request = std::make_shared<WriteRequest>(Ex_, StreamId_, Buffer);
            WriteQueue_.push_back(Request);
            StartWriter();

            boost::system::error_code WaitEc;
            std::size_t Written = 0;
            try
            {
                Written = co_await Request->Done->async_receive(
                    Net::redirect_error(Net::use_awaitable, WaitEc));
            }
            catch (...)
            {
                ErrorCode = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (WaitEc)
            {
                ErrorCode = std::make_error_code(std::errc::io_error);
                co_return Written;
            }
            ErrorCode.clear();
            co_return Written;
        }

        void Close() override
        {
            Closed_ = true;
            Notify_.cancel();
            FailQueued(boost::system::errc::make_error_code(boost::system::errc::not_connected));
        }

        void Cancel() override
        {
            Close();
        }

        /**
         * @brief 半关闭 XHTTP 请求方向
         * @details 发送 END_STREAM，但继续保留响应方向，供标准 HTTP/2
         *          服务器在收到完整请求体后返回 echo 或最终响应。
         */
        [[nodiscard]] auto Finish() -> Net::awaitable<void>
        {
            if (Closed_ || Finished_ || StreamId_ < 0 || !FinishFn_)
            {
                throw std::system_error(std::make_error_code(std::errc::not_connected));
            }
            Finished_ = true;
            auto Request = std::make_shared<WriteRequest>(Ex_, StreamId_, std::span<const std::byte>{}, true);
            WriteQueue_.push_back(Request);
            StartWriter();

            boost::system::error_code WaitEc;
            try
            {
                (void)co_await Request->Done->async_receive(
                    Net::redirect_error(Net::use_awaitable, WaitEc));
            }
            catch (...)
            {
                throw std::system_error(std::make_error_code(std::errc::not_connected));
            }
            if (WaitEc)
            {
                throw std::system_error(std::make_error_code(std::errc::io_error));
            }
        }

        [[nodiscard]] auto NextLayer() noexcept -> Transmission * override
        {
            return nullptr;
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Transmission * override
        {
            return nullptr;
        }

        /**
         * @brief 投递收到的 DATA 载荷
         * @param Data 载荷字节
         */
        void Push(std::span<const std::byte> Data)
        {
            if (Closed_ || Data.empty())
            {
                return;
            }
            std::vector<std::byte> copy(Data.begin(), Data.end());
            if (!Notify_.try_send(boost::system::error_code{}, std::move(copy)))
            {
                Diagnose::Error("xhttp receive channel full; closing Stream");
                Close();
            }
        }

        /**
         * @brief 对端 END_STREAM（流关闭）
         */
        void NotifyEof()
        {
            if (!Closed_ && !Eof_ && !EofPending_)
            {
                if (!Notify_.try_send(boost::system::error_code{},
                                      std::vector<std::byte>{}))
                {
                    EofPending_ = true;
                }
            }
        }

        /**
         * @brief 绑定匹配流 ID 并 flush 缓冲写
         * @param StreamId 匹配的 h2 流 ID
         */
        void BindStream(std::int32_t StreamId)
        {
            if (Closed_ || StreamId_ >= 0)
            {
                return;
            }
            StreamId_ = StreamId;
            if (!WritePending_.empty() && WriteFn_)
            {
                QueueWrite(std::move(WritePending_), {});
            }
        }

        /// 当前匹配流 ID（-1 = 未匹配）
        std::int32_t StreamId_{-1};

    private:
        using CompletionChannel = Net::experimental::channel<void(boost::system::error_code, std::size_t)>;

        struct WriteRequest
        {
            WriteRequest(Net::any_io_executor Executor, std::int32_t StreamId,
                         std::span<const std::byte> Data, bool EndStream = false)
                : StreamId(StreamId), Data(Data.begin(), Data.end()), EndStream(EndStream),
                  Done(std::make_shared<CompletionChannel>(Executor, 1))
            {
            }

            std::int32_t StreamId;
            std::vector<std::byte> Data;
            bool EndStream{false};
            std::shared_ptr<CompletionChannel> Done;
        };

        void QueueWrite(std::vector<std::byte> Data,
                        std::shared_ptr<CompletionChannel> Completion)
        {
            if (Data.empty() || Closed_ || !WriteFn_)
            {
                return;
            }
            auto Request = std::make_shared<WriteRequest>(Ex_, StreamId_, Data);
            Request->Done = std::move(Completion);
            WriteQueue_.push_back(std::move(Request));
            StartWriter();
        }

        void StartWriter()
        {
            if (WriterRunning_ || Closed_ || WriteQueue_.empty())
            {
                return;
            }
            WriterRunning_ = true;
            auto Self = std::static_pointer_cast<XhttpTransport>(Transmission::shared_from_this());
            Net::co_spawn(Ex_, [Self]() -> Net::awaitable<void> { co_await Self->WriteLoop(); }, Net::detached);
        }

        void FailQueued(boost::system::error_code Ec)
        {
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                if (Request->Done)
                {
                    (void)Request->Done->try_send(Ec, 0);
                }
            }
        }

        auto WriteLoop() -> Net::awaitable<void>
        {
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                boost::system::error_code WriteEc;
                std::size_t Written = 0;
                try
                {
                    if (!Closed_ && ((Request->EndStream && FinishFn_) ||
                                     (!Request->EndStream && WriteFn_)))
                    {
                        if (Request->EndStream)
                        {
                            co_await FinishFn_(Request->StreamId);
                        }
                        else
                        {
                            co_await WriteFn_(Request->StreamId,
                                              std::span<const std::byte>(Request->Data));
                        }
                        Written = Request->Data.size();
                    }
                    else
                    {
                        WriteEc = boost::system::errc::make_error_code(boost::system::errc::not_connected);
                    }
                }
                catch (...)
                {
                    WriteEc = boost::system::errc::make_error_code(boost::system::errc::io_error);
                }

                if (Request->Done)
                {
                    (void)Request->Done->try_send(WriteEc, Written);
                }
                if (WriteEc)
                {
                    Closed_ = true;
                    FailQueued(WriteEc);
                    break;
                }
            }
            WriterRunning_ = false;
            co_return;
        }

        using ChannelType =
            Net::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::byte>)>;

        Net::any_io_executor Ex_;
        WriteCb WriteFn_;
        FinishCb FinishFn_;
        ChannelType Notify_;
        std::vector<std::byte> RxCurrent_;
        std::size_t RxOffset_{0};
        std::vector<std::byte> WritePending_; ///< 匹配前的写缓冲
        std::deque<std::shared_ptr<WriteRequest>> WriteQueue_;
        bool WriterRunning_{false};
        bool Closed_{false};
        bool Finished_{false};
        bool Eof_{false};
        bool EofPending_{false};
    };

    /**
     * @class SplitTransport
     * @brief XHTTP Stream-up/Packet-up 的逻辑双向传输。
     * @details 读写方向由调用方绑定到不同的 HTTP/2 stream：读侧消费下行
     *          GET 的 DATA，写侧提交上行 POST（Packet-up 每次写入新开一个 POST）。
     */
    class SplitTransport final : public Transmission
    {
    public:
        using WriteCb = std::function<Net::awaitable<void>(std::span<const std::byte>)>;
        using CloseCb = std::function<void()>;

        SplitTransport(Net::any_io_executor Executor, WriteCb WriteFunction, CloseCb CloseFunction = {})
            : Ex_(std::move(Executor)),
              WriteFn_(std::move(WriteFunction)),
              CloseFn_(std::move(CloseFunction)),
              Notify_(Ex_, 64)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        [[nodiscard]] auto async_read_some(
            std::span<std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (Buffer.empty())
            {
                ErrorCode.clear();
                co_return 0;
            }
            while (RxOffset_ >= RxCurrent_.size())
            {
                if (Closed_)
                {
                    ErrorCode = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Eof_)
                {
                    ErrorCode.clear();
                    co_return 0;
                }
                if (EofPending_ && !Notify_.ready())
                {
                    EofPending_ = false;
                    Eof_ = true;
                    ErrorCode.clear();
                    co_return 0;
                }
                boost::system::error_code ChannelError;
                auto Block = co_await Notify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, ChannelError));
                if (ChannelError)
                {
                    ErrorCode = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Block.empty())
                {
                    Eof_ = true;
                    ErrorCode.clear();
                    co_return 0;
                }
                RxCurrent_ = std::move(Block);
                RxOffset_ = 0;
            }
            const auto Count = (std::min)(Buffer.size(), RxCurrent_.size() - RxOffset_);
            std::memcpy(Buffer.data(), RxCurrent_.data() + RxOffset_, Count);
            RxOffset_ += Count;
            ErrorCode.clear();
            co_return Count;
        }

        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            if (Buffer.empty())
            {
                ErrorCode.clear();
                co_return 0;
            }
            if (Closed_ || !WriteFn_)
            {
                ErrorCode = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            auto Request = std::make_shared<WriteRequest>(Ex_, Buffer);
            WriteQueue_.push_back(Request);
            StartWriter();

            boost::system::error_code WaitError;
            std::size_t Written = 0;
            try
            {
                Written = co_await Request->Done->async_receive(
                    Net::redirect_error(Net::use_awaitable, WaitError));
            }
            catch (...)
            {
                ErrorCode = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (WaitError)
            {
                ErrorCode = std::make_error_code(std::errc::io_error);
                co_return Written;
            }
            ErrorCode.clear();
            co_return Written;
        }

        void Close() override
        {
            if (Closed_)
            {
                return;
            }
            Closed_ = true;
            Notify_.cancel();
            FailQueued(boost::system::errc::make_error_code(boost::system::errc::not_connected));
            NotifyClose();
        }

        void Cancel() override
        {
            Close();
        }

        void Push(std::span<const std::byte> Data)
        {
            if (Closed_ || Data.empty())
            {
                return;
            }
            std::vector<std::byte> Copy(Data.begin(), Data.end());
            if (!Notify_.try_send(boost::system::error_code{}, std::move(Copy)))
            {
                Close();
            }
        }

        void NotifyEof()
        {
            if (!Closed_ && !Eof_ && !EofPending_)
            {
                if (!Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{}))
                {
                    EofPending_ = true;
                }
            }
        }

    private:
        using CompletionChannel = Net::experimental::channel<void(boost::system::error_code, std::size_t)>;

        struct WriteRequest final
        {
            WriteRequest(Net::any_io_executor Executor, std::span<const std::byte> Bytes)
                : Data(Bytes.begin(), Bytes.end()), Done(std::make_shared<CompletionChannel>(Executor, 1))
            {
            }

            std::vector<std::byte> Data;
            std::shared_ptr<CompletionChannel> Done;
        };

        void StartWriter()
        {
            if (WriterRunning_ || Closed_ || WriteQueue_.empty())
            {
                return;
            }
            WriterRunning_ = true;
            auto Self = std::static_pointer_cast<SplitTransport>(Transmission::shared_from_this());
            Net::co_spawn(Ex_, [Self]() -> Net::awaitable<void> { co_await Self->WriteLoop(); }, Net::detached);
        }

        void FailQueued(boost::system::error_code ErrorCode)
        {
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                (void)Request->Done->try_send(ErrorCode, 0);
            }
        }

        void NotifyClose()
        {
            if (CloseNotified_)
            {
                return;
            }
            CloseNotified_ = true;
            if (CloseFn_)
            {
                CloseFn_();
            }
        }

        auto WriteLoop() -> Net::awaitable<void>
        {
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                boost::system::error_code WriteError;
                std::size_t Written = 0;
                try
                {
                    if (Closed_ || !WriteFn_)
                    {
                        WriteError = boost::system::errc::make_error_code(
                            boost::system::errc::not_connected);
                    }
                    else
                    {
                        co_await WriteFn_(Request->Data);
                        Written = Request->Data.size();
                    }
                }
                catch (...)
                {
                    WriteError = boost::system::errc::make_error_code(boost::system::errc::io_error);
                }
                (void)Request->Done->try_send(WriteError, Written);
                if (WriteError)
                {
                    Closed_ = true;
                    FailQueued(WriteError);
                    NotifyClose();
                    break;
                }
            }
            WriterRunning_ = false;
            co_return;
        }

        using ChannelType =
            Net::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::byte>)>;

        Net::any_io_executor Ex_;
        WriteCb WriteFn_;
        CloseCb CloseFn_;
        ChannelType Notify_;
        std::vector<std::byte> RxCurrent_;
        std::size_t RxOffset_{0};
        std::deque<std::shared_ptr<WriteRequest>> WriteQueue_;
        bool WriterRunning_{false};
        bool Closed_{false};
        bool CloseNotified_{false};
        bool Eof_{false};
        bool EofPending_{false};
    };

    struct SplitPath final
    {
        std::string Session;
        std::uint64_t Sequence{0};
        bool HasSequence{false};
    };

    [[nodiscard]] inline auto MakeSplitPath(
        std::string_view Base,
        std::string_view Session,
        const std::optional<std::uint64_t> Sequence = std::nullopt) -> std::string
    {
        std::string Result(Base == "/" ? std::string{} : std::string(Base));
        if (Result.empty() || Result.back() != '/')
        {
            Result.push_back('/');
        }
        Result.append(Session);
        if (Sequence)
        {
            Result.push_back('/');
            Result.append(std::to_string(*Sequence));
        }
        return Result;
    }

    [[nodiscard]] inline auto ParseSplitPath(
        std::string_view Base,
        std::string_view Path,
        const bool RequireSequence) -> std::optional<SplitPath>
    {
        std::string Prefix(Base);
        if (Prefix.empty() || Prefix.back() != '/')
        {
            Prefix.push_back('/');
        }
        if (Path.rfind(Prefix, 0) != 0)
        {
            return std::nullopt;
        }
        auto Suffix = Path.substr(Prefix.size());
        if (Suffix.empty())
        {
            return std::nullopt;
        }
        const auto Separator = Suffix.find('/');
        SplitPath Result;
        if (Separator == std::string_view::npos)
        {
            if (RequireSequence)
            {
                return std::nullopt;
            }
            Result.Session = std::string(Suffix);
            return Result;
        }
        if (RequireSequence && Separator + 1 >= Suffix.size())
        {
            return std::nullopt;
        }
        if (!RequireSequence || Separator == 0 || Suffix.find('/', Separator + 1) != std::string_view::npos)
        {
            return std::nullopt;
        }
        Result.Session = std::string(Suffix.substr(0, Separator));
        const auto SequenceText = Suffix.substr(Separator + 1);
        const auto [End, Error] = std::from_chars(
            SequenceText.data(), SequenceText.data() + SequenceText.size(), Result.Sequence);
        if (Result.Session.empty() || Error != std::errc{} || End != SequenceText.data() + SequenceText.size())
        {
            return std::nullopt;
        }
        Result.HasSequence = true;
        return Result;
    }

    [[nodiscard]] inline auto NextSplitSessionId() -> std::string
    {
        static std::atomic<std::uint64_t> Counter{1};
        const auto Value = Counter.fetch_add(1, std::memory_order_relaxed);
        char Buffer[32]{};
        const auto [End, Error] = std::to_chars(Buffer, Buffer + sizeof(Buffer), Value, 16);
        if (Error != std::errc{})
        {
            return "1";
        }
        return std::string(Buffer, End);
    }

    /**
     * @class XhttpAccept
     * @brief XHTTP 服务端握手编排（TLS + h2 + Stream-one 匹配）
     */
    class XhttpAccept : public std::enable_shared_from_this<XhttpAccept>
    {
    public:
        /**
         * @brief 构造
         * @param Raw 底层传输（所有权转移）
         * @param SslCtx TLS 服务端上下文
         * @param ConfigValue XHTTP 配置
         */
        XhttpAccept(
            SharedTransmission Raw,
            Net::ssl::context &SslCtx,
            const Config &ConfigValue)
            : Raw_(std::move(Raw)), SslCtx_(SslCtx), Cfg_(ConfigValue)
        {
        }

        /**
         * @brief 执行握手并等待流匹配
         * @return 匹配流的双向传输；失败返回 nullptr
         */
        [[nodiscard]] auto Run() -> Net::awaitable<SharedTransmission>
        {
            if (!Raw_)
            {
                co_return nullptr;
            }
            auto [Code, Stream, Recovered] =
                co_await Preview::Transport::Encrypted::SslHandshake(std::move(Raw_), SslCtx_);
            if (Code != Preview::Fault::Code::Success || !Stream)
            {
                if (Recovered)
                {
                    Recovered->Cancel();
                    Recovered->Close();
                }
                co_return nullptr;
            }
            Encrypted_ = std::make_shared<Preview::Transport::Encrypted>(std::move(Stream));

            Session_ = std::make_shared<h2::SessionImpl>(Encrypted_->Executor(), true);
            auto Wire = std::make_shared<WireWriter>(
                Encrypted_->Executor(),
                [Encrypted = Encrypted_](std::span<const std::byte> Data) -> Net::awaitable<void>
                {
                    std::error_code ErrorCode;
                    const auto N = co_await Encrypted->AsyncWrite(Data, ErrorCode);
                    if (ErrorCode || N != Data.size())
                    {
                        if (ErrorCode)
                        {
                            throw std::system_error(ErrorCode);
                        }
                        throw std::system_error(std::make_error_code(std::errc::io_error));
                    }
                    co_return;
                });

            // 写回调捕获共享状态，所有物理写入经过同一串行器。
            auto Session = Session_;
            Transport_ = std::make_shared<XhttpTransport>(
                Encrypted_->Executor(),
                [Session, Wire](std::int32_t StreamId, std::span<const std::byte> Data)
                    -> Net::awaitable<void>
                {
                    (void)Session->SubmitData(StreamId, Data, false);
                    std::vector<std::byte> Output;
                    if (Session->Collect(Output) && !Output.empty())
                    {
                        co_await Wire->Write(Output);
                    }
                    co_return;
                });

            Session_->OnHeaders = [Transport = Transport_, Session = Session_,
                                   PathValue = Cfg_.Path, HostValue = Cfg_.Host]
                (std::int32_t StreamId, const h2::HeaderList &Headers, bool)
            {
                if (Transport->StreamId_ >= 0)
                {
                    return;
                }
                bool IsPost = false;
                bool HostOk = HostValue.empty();
                std::string_view Path;
                for (const auto &Header : Headers)
                {
                    if (Header.Name == ":method" && Header.value == "POST")
                    {
                        IsPost = true;
                    }
                    else if (Header.Name == ":path")
                    {
                        Path = Header.value;
                    }
                    else if (Header.Name == ":authority")
                    {
                        HostOk = HostValue.empty() || Header.value == HostValue;
                    }
                }
                const std::string_view Base(PathValue.data(), PathValue.size());
                bool PathOk;
                if (Base == "/")
                {
                    PathOk = Path.rfind('/', 0) == 0;
                }
                else
                {
                    PathOk = Path.rfind(Base, 0) == 0;
                }
                if (IsPost && PathOk && HostOk)
                {
                    Transport->BindStream(StreamId);
                    h2::HeaderList Response = {{":status", "200"}, {"content-type", "text/event-stream"}};
                    (void)Session->SubmitHeaders(StreamId, Response, false);
                }
            };
            Session_->OnData = [Transport = Transport_](std::int32_t StreamId,
                                                        std::span<const std::byte> Data)
            {
                if (StreamId == Transport->StreamId_)
                {
                    Transport->Push(Data);
                }
            };
            Session_->OnStreamClose = [Transport = Transport_](std::int32_t StreamId, std::uint32_t)
            {
                if (StreamId == Transport->StreamId_)
                {
                    Transport->NotifyEof();
                }
            };

            // driver 与数据回调共享同一个物理写入器。
            auto Transport = Transport_;
            Net::co_spawn(Encrypted_->Executor(),
                          [Session, Wire, Transport, Encrypted = Encrypted_]() mutable -> Net::awaitable<void>
                          {
                              std::array<std::byte, 16384> Buffer{};
                              while (true)
                              {
                                  std::error_code ErrorCode;
                                  const auto N = co_await Encrypted->async_read_some(Buffer, ErrorCode);
                                  if (ErrorCode || N == 0)
                                  {
                                      break;
                                  }
                                  if (N > Buffer.size())
                                  {
                                      break;
                                  }
                                  if (!Session->Feed(
                                          std::span<const std::byte>(Buffer.data(), N),
                                          ErrorCode) &&
                                      ErrorCode != make_error_code(Error::NeedMore))
                                  {
                                      break;
                                  }
                                  std::vector<std::byte> Output;
                                  if (Session->Collect(Output) && !Output.empty())
                                  {
                                      try
                                      {
                                          co_await Wire->Write(Output);
                                      }
                                      catch (...)
                                      {
                                          break;
                                      }
                                  }
                              }
                              Transport->NotifyEof();
                              co_return;
                          },
                          Net::detached);
            co_return Transport_;
        }

    private:
        SharedTransmission Raw_;
        Net::ssl::context &SslCtx_;
        Config Cfg_;
        Preview::SharedTransmission Encrypted_;
        SharedH2Session Session_;
        std::shared_ptr<XhttpTransport> Transport_;
    };

    using SplitReadyChannel = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct SplitServerState final
    {
        std::shared_ptr<Preview::Transport::Encrypted> Encrypted;
        SharedH2Session Session;
        std::shared_ptr<WireWriter> Wire;
        std::shared_ptr<SplitReadyChannel> Ready;
        std::shared_ptr<SplitTransport> Transport;
        Config Cfg;
        std::string SessionId;
        std::int32_t UploadStream{-1};
        std::int32_t DownloadStream{-1};
        bool UploadEnded{false};
        bool ReadySignaled{false};
        std::vector<std::vector<std::byte>> PendingUpload;
        std::map<std::int32_t, std::vector<std::byte>> PacketBodies;
    };

    [[nodiscard]] inline auto FlushSplitSession(const std::shared_ptr<SplitServerState> &State)
        -> Net::awaitable<void>
    {
        std::vector<std::byte> Output;
        if (State->Session->Collect(Output) && !Output.empty())
        {
            co_await State->Wire->Write(Output);
        }
        co_return;
    }

    inline auto SignalSplitReady(
        const std::shared_ptr<SplitServerState> &State,
        const bool Accepted) -> void
    {
        if (State->ReadySignaled)
        {
            return;
        }
        State->ReadySignaled = true;
        (void)State->Ready->try_send(boost::system::error_code{}, Accepted);
    }

    inline auto PushSplitServerData(
        const std::shared_ptr<SplitServerState> &State,
        std::span<const std::byte> Data) -> void
    {
        if (Data.empty())
        {
            return;
        }
        if (State->Transport)
        {
            State->Transport->Push(Data);
            return;
        }
        State->PendingUpload.emplace_back(Data.begin(), Data.end());
    }

    [[nodiscard]] inline auto MakeSplitResponse(const std::string_view Status, const bool EndStream)
        -> h2::HeaderList
    {
        (void)EndStream;
        return {{":status", std::string(Status)},
                {"content-type", "text/event-stream"},
                {"cache-control", "no-cache"}};
    }

    inline auto RejectSplitRequest(
        const std::shared_ptr<SplitServerState> &State,
        const std::int32_t StreamId) -> void
    {
        (void)State->Session->SubmitHeaders(
            StreamId,
            MakeSplitResponse("404", true),
            true);
    }

    inline auto BindSplitServerTransport(const std::shared_ptr<SplitServerState> &State) -> void
    {
        if (State->Transport || State->DownloadStream < 0)
        {
            return;
        }
        State->Transport = std::make_shared<SplitTransport>(
            State->Encrypted->Executor(),
            [State](std::span<const std::byte> Data) -> Net::awaitable<void>
            {
                if (State->DownloadStream < 0 ||
                    State->Session->SubmitData(State->DownloadStream, Data, false) != 0)
                {
                    throw std::system_error(std::make_error_code(std::errc::broken_pipe));
                }
                co_await FlushSplitSession(State);
            },
            [State]()
            {
                State->Wire->Close();
                State->Encrypted->Close();
            });
        for (auto &Pending : State->PendingUpload)
        {
            State->Transport->Push(Pending);
        }
        State->PendingUpload.clear();
        if (State->UploadEnded)
        {
            State->Transport->NotifyEof();
        }
    }

    inline auto HandleSplitServerHeaders(
        const std::shared_ptr<SplitServerState> &State,
        const std::int32_t StreamId,
        const h2::HeaderList &Headers,
        const bool EndStream) -> void
    {
        bool IsGet = false;
        bool IsPost = false;
        bool HostOk = State->Cfg.Host.empty();
        std::string_view Path;
        for (const auto &Header : Headers)
        {
            if (Header.Name == ":method")
            {
                IsGet = Header.value == "GET";
                IsPost = Header.value == "POST";
            }
            else if (Header.Name == ":path")
            {
                Path = Header.value;
            }
            else if (Header.Name == ":authority")
            {
                HostOk = State->Cfg.Host.empty() || Header.value == State->Cfg.Host;
            }
        }

        const auto Parsed = ParseSplitPath(
            State->Cfg.Path,
            Path,
            State->Cfg.Mode == "PacketUp" && IsPost);
        const auto IsDownstream = IsGet && Parsed && !Parsed->HasSequence;
        const auto IsStreamUpload = State->Cfg.Mode == "StreamUp" && IsPost && Parsed &&
                                    !Parsed->HasSequence;
        const auto IsPacketUpload = State->Cfg.Mode == "PacketUp" && IsPost && Parsed &&
                                    Parsed->HasSequence;
        if (!HostOk || !Parsed || (!IsDownstream && !IsStreamUpload && !IsPacketUpload))
        {
            RejectSplitRequest(State, StreamId);
            return;
        }
        if (State->SessionId.empty())
        {
            State->SessionId = Parsed->Session;
        }
        if (State->SessionId != Parsed->Session)
        {
            RejectSplitRequest(State, StreamId);
            return;
        }
        if (IsDownstream)
        {
            if (State->DownloadStream >= 0)
            {
                RejectSplitRequest(State, StreamId);
                return;
            }
            State->DownloadStream = StreamId;
            (void)State->Session->SubmitHeaders(
                StreamId,
                MakeSplitResponse("200", false),
                false);
            BindSplitServerTransport(State);
            SignalSplitReady(State, true);
            return;
        }
        if (IsStreamUpload)
        {
            if (State->UploadStream >= 0)
            {
                RejectSplitRequest(State, StreamId);
                return;
            }
            State->UploadStream = StreamId;
            (void)State->Session->SubmitHeaders(
                StreamId,
                MakeSplitResponse("200", false),
                false);
            if (EndStream)
            {
                State->UploadEnded = true;
            }
            return;
        }

        State->PacketBodies.emplace(StreamId, std::vector<std::byte>{});
        (void)State->Session->SubmitHeaders(
            StreamId,
            MakeSplitResponse("200", true),
            false);
        if (EndStream)
        {
            State->PacketBodies.erase(StreamId);
        }
    }

    inline auto HandleSplitServerData(
        const std::shared_ptr<SplitServerState> &State,
        const std::int32_t StreamId,
        std::span<const std::byte> Data) -> void
    {
        if (State->Cfg.Mode == "StreamUp" && StreamId == State->UploadStream)
        {
            PushSplitServerData(State, Data);
            return;
        }
        const auto Packet = State->PacketBodies.find(StreamId);
        if (Packet != State->PacketBodies.end())
        {
            Packet->second.insert(Packet->second.end(), Data.begin(), Data.end());
        }
    }

    inline auto HandleSplitServerClose(
        const std::shared_ptr<SplitServerState> &State,
        const std::int32_t StreamId,
        const std::uint32_t ErrorCode) -> void
    {
        if (State->Cfg.Mode == "StreamUp" && StreamId == State->UploadStream)
        {
            State->UploadEnded = true;
            if (State->Transport && ErrorCode == h2::ErrorNoError)
            {
                State->Transport->NotifyEof();
            }
            return;
        }
        const auto Packet = State->PacketBodies.find(StreamId);
        if (Packet != State->PacketBodies.end())
        {
            if (ErrorCode == h2::ErrorNoError)
            {
                PushSplitServerData(State, Packet->second);
                (void)State->Session->SubmitData(StreamId, {}, true);
            }
            State->PacketBodies.erase(Packet);
        }
        if (StreamId == State->DownloadStream && ErrorCode != h2::ErrorNoError && State->Transport)
        {
            State->Transport->NotifyEof();
        }
    }

    class XhttpSplitAccept final : public std::enable_shared_from_this<XhttpSplitAccept>
    {
    public:
        XhttpSplitAccept(SharedTransmission Raw, Net::ssl::context &SslCtx, Config Cfg)
            : Raw_(std::move(Raw)), SslCtx_(SslCtx), Cfg_(std::move(Cfg))
        {
        }

        [[nodiscard]] auto Run() -> Net::awaitable<SharedTransmission>
        {
            if (!Raw_ || !Cfg_.IsSplit())
            {
                co_return nullptr;
            }
            auto [Code, Stream, Recovered] =
                co_await Preview::Transport::Encrypted::SslHandshake(std::move(Raw_), SslCtx_);
            if (Code != Preview::Fault::Code::Success || !Stream)
            {
                if (Recovered)
                {
                    Recovered->Cancel();
                    Recovered->Close();
                }
                co_return nullptr;
            }

            auto State = std::make_shared<SplitServerState>();
            State->Cfg = Cfg_;
            State->Encrypted = std::make_shared<Preview::Transport::Encrypted>(std::move(Stream));
            State->Session = std::make_shared<h2::SessionImpl>(State->Encrypted->Executor(), true);
            State->Ready = std::make_shared<SplitReadyChannel>(State->Encrypted->Executor(), 1);
            State->Wire = std::make_shared<WireWriter>(
                State->Encrypted->Executor(),
                [Encrypted = State->Encrypted](std::span<const std::byte> Data) -> Net::awaitable<void>
                {
                    std::error_code ErrorCode;
                    const auto Written = co_await Encrypted->AsyncWrite(Data, ErrorCode);
                    if (ErrorCode || Written != Data.size())
                    {
                        throw std::system_error(
                            ErrorCode ? ErrorCode : std::make_error_code(std::errc::io_error));
                    }
                });
            State->Session->OnHeaders = [State](std::int32_t StreamId,
                                                  const h2::HeaderList &Headers,
                                                  bool EndStream)
            {
                HandleSplitServerHeaders(State, StreamId, Headers, EndStream);
            };
            State->Session->OnData = [State](std::int32_t StreamId, std::span<const std::byte> Data)
            {
                HandleSplitServerData(State, StreamId, Data);
            };
            State->Session->OnStreamClose = [State](std::int32_t StreamId, std::uint32_t ErrorCode)
            {
                HandleSplitServerClose(State, StreamId, ErrorCode);
            };
            State->Session->SendSettings();

            Net::co_spawn(
                State->Encrypted->Executor(),
                [State]() -> Net::awaitable<void>
                {
                    std::array<std::byte, 16384> Buffer{};
                    while (true)
                    {
                        std::error_code ErrorCode;
                        const auto Read = co_await State->Encrypted->async_read_some(Buffer, ErrorCode);
                        if (ErrorCode || Read == 0 || Read > Buffer.size())
                        {
                            break;
                        }
                        if (!State->Session->Feed(
                                std::span<const std::byte>(Buffer.data(), Read), ErrorCode) &&
                            ErrorCode != make_error_code(Error::NeedMore))
                        {
                            break;
                        }
                        try
                        {
                            co_await FlushSplitSession(State);
                        }
                        catch (...)
                        {
                            break;
                        }
                    }
                    if (!State->ReadySignaled)
                    {
                        SignalSplitReady(State, false);
                    }
                    if (State->Transport)
                    {
                        State->Transport->NotifyEof();
                    }
                },
                Net::detached);

            try
            {
                co_await FlushSplitSession(State);
            }
            catch (...)
            {
                State->Encrypted->Close();
                co_return nullptr;
            }

            boost::system::error_code ReadyError;
            Net::steady_timer Deadline(State->Encrypted->Executor());
            Deadline.expires_after(std::chrono::seconds(30));
            auto Wait = State->Ready->async_receive(
                Net::redirect_error(Net::use_awaitable, ReadyError));
            const auto Result = co_await (std::move(Wait) || Deadline.async_wait(Net::use_awaitable));
            if (Result.index() == 1 || ReadyError || !std::get<0>(Result) || !State->Transport)
            {
                State->Wire->Close();
                State->Encrypted->Close();
                co_return nullptr;
            }
            co_return State->Transport;
        }

    private:
        SharedTransmission Raw_;
        Net::ssl::context &SslCtx_;
        Config Cfg_;
    };

    /**
     * @brief 建立 XHTTP 客户端 TLS 连接
     * @param Raw 底层传输（所有权转移）
     * @param SslCtx TLS 客户端上下文
     * @param Host SNI 主机名
     * @return 完成 TLS 握手的流；失败返回空
     */
    [[nodiscard]] inline auto ConnectTls(
        SharedTransmission Raw,
        Net::ssl::context &SslCtx,
        std::string_view Host) -> Net::awaitable<Preview::Transport::Encrypted::SharedStream>
    {
        if (!Raw)
        {
            co_return nullptr;
        }

        Preview::Transport::Connector Connector(std::move(Raw), {});
        auto Stream = std::make_shared<Preview::Transport::Encrypted::StreamType>(
            std::move(Connector), SslCtx);
        if (!Host.empty())
        {
            const auto HostName = std::string(Host);
            if (SSL_set_tlsext_host_name(Stream->native_handle(), HostName.c_str()) != 1)
            {
                auto Recovered = Stream->next_layer().Release();
                if (Recovered)
                {
                    Recovered->Close();
                }
                co_return nullptr;
            }
        }

        // XHTTP stream-one 使用标准 HTTP/2 ALPN，避免把 TLS 连接误协商为 HTTP/1.1。
        constexpr unsigned char Alpn[] = {2, 'h', '2'};
        if (SSL_set_alpn_protos(Stream->native_handle(), Alpn, sizeof(Alpn)) != 0)
        {
            auto Recovered = Stream->next_layer().Release();
            if (Recovered)
            {
                Recovered->Close();
            }
            co_return nullptr;
        }

        Net::steady_timer Deadline(Stream->get_executor());
        Deadline.expires_after(std::chrono::seconds(30));
        auto DoHandshake = [Stream]() -> Net::awaitable<boost::system::error_code>
        {
            boost::system::error_code Error;
            co_await Stream->async_handshake(
                Net::ssl::stream_base::client,
                Net::redirect_error(Net::use_awaitable, Error));
            co_return Error;
        };
        const auto Result = co_await (DoHandshake() || Deadline.async_wait(Net::use_awaitable));
        const auto Failed = Result.index() == 1 || std::get<0>(Result);
        if (Failed)
        {
            auto Recovered = Stream->next_layer().Release();
            if (Recovered)
            {
                Recovered->Cancel();
                Recovered->Close();
            }
            co_return nullptr;
        }
        co_return Stream;
    }

    using ResponseChannel = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct SplitClientState final
    {
        std::shared_ptr<Preview::Transport::Encrypted> Encrypted;
        SharedH2Session Session;
        std::shared_ptr<WireWriter> Wire;
        std::shared_ptr<SplitTransport> Transport;
        std::shared_ptr<ResponseChannel> Response;
        Config Cfg;
        std::string Host;
        std::string SessionId;
        std::int32_t UploadStream{-1};
        std::int32_t DownloadStream{-1};
        std::uint64_t NextSequence{0};
    };

    [[nodiscard]] inline auto FlushSplitClient(const std::shared_ptr<SplitClientState> &State)
        -> Net::awaitable<void>
    {
        std::vector<std::byte> Output;
        if (State->Session->Collect(Output) && !Output.empty())
        {
            co_await State->Wire->Write(Output);
        }
        co_return;
    }

    inline auto CloseSplitClient(const std::shared_ptr<SplitClientState> &State) -> void
    {
        State->Transport->Close();
        State->Wire->Close();
        State->Encrypted->Close();
    }

    [[nodiscard]] inline auto MakeSplitClientState(
        Preview::Transport::Encrypted::SharedStream Stream,
        const Config &Cfg,
        std::string Host) -> std::shared_ptr<SplitClientState>
    {
        auto State = std::make_shared<SplitClientState>();
        State->Cfg = Cfg;
        State->Host = std::move(Host);
        State->SessionId = NextSplitSessionId();
        State->Encrypted = std::make_shared<Preview::Transport::Encrypted>(std::move(Stream));
        State->Session = std::make_shared<h2::SessionImpl>(State->Encrypted->Executor(), false);
        State->Wire = std::make_shared<WireWriter>(
            State->Encrypted->Executor(),
            [Encrypted = State->Encrypted](std::span<const std::byte> Data) -> Net::awaitable<void>
            {
                std::error_code ErrorCode;
                const auto Written = co_await Encrypted->AsyncWrite(Data, ErrorCode);
                if (ErrorCode || Written != Data.size())
                {
                    throw std::system_error(
                        ErrorCode ? ErrorCode : std::make_error_code(std::errc::io_error));
                }
            });
        State->Response = std::make_shared<ResponseChannel>(State->Encrypted->Executor(), 1);
        State->Session->OnHeaders = [State](std::int32_t StreamId,
                                              const h2::HeaderList &Headers,
                                              bool)
        {
            if (StreamId != State->DownloadStream)
            {
                return;
            }
            bool StatusOk = false;
            for (const auto &Header : Headers)
            {
                if (Header.Name == ":status" && Header.value == "200")
                {
                    StatusOk = true;
                }
            }
            (void)State->Response->try_send(boost::system::error_code{}, StatusOk);
        };
        State->Session->OnData = [State](std::int32_t StreamId, std::span<const std::byte> Data)
        {
            if (StreamId == State->DownloadStream && State->Transport)
            {
                State->Transport->Push(Data);
            }
        };
        State->Session->OnStreamClose = [State](std::int32_t StreamId, std::uint32_t ErrorCode)
        {
            if (StreamId == State->DownloadStream && State->Transport &&
                ErrorCode == h2::ErrorNoError)
            {
                State->Transport->NotifyEof();
            }
        };
        State->Transport = std::make_shared<SplitTransport>(
            State->Encrypted->Executor(),
            [State](std::span<const std::byte> Data) -> Net::awaitable<void>
            {
                std::int32_t StreamId = State->UploadStream;
                if (State->Cfg.Mode == "PacketUp")
                {
                    const auto Path = MakeSplitPath(
                        State->Cfg.Path,
                        State->SessionId,
                        State->NextSequence++);
                    StreamId = State->Session->OpenStream(
                        {{":method", "POST"},
                         {":path", Path},
                         {":scheme", "https"},
                         {":authority", State->Host},
                         {"content-type", "application/octet-stream"}},
                        false);
                    if (StreamId < 0)
                    {
                        throw std::system_error(std::make_error_code(std::errc::broken_pipe));
                    }
                }
                const auto EndStream = State->Cfg.Mode == "PacketUp";
                if (StreamId < 0 || State->Session->SubmitData(StreamId, Data, EndStream) != 0)
                {
                    throw std::system_error(std::make_error_code(std::errc::broken_pipe));
                }
                co_await FlushSplitClient(State);
            },
            [State]()
            {
                State->Wire->Close();
                State->Encrypted->Close();
            });
        return State;
    }

    [[nodiscard]] inline auto OpenSplitClientStreams(
        const std::shared_ptr<SplitClientState> &State) -> bool
    {
        State->Session->SendSettings();
        const auto DownPath = MakeSplitPath(State->Cfg.Path, State->SessionId);
        if (State->Cfg.Mode == "StreamUp")
        {
            State->UploadStream = State->Session->OpenStream(
                {{":method", "POST"},
                 {":path", DownPath},
                 {":scheme", "https"},
                 {":authority", State->Host},
                 {"content-type", "application/octet-stream"}},
                false);
            if (State->UploadStream < 0)
            {
                return false;
            }
        }
        State->DownloadStream = State->Session->OpenStream(
            {{":method", "GET"},
             {":path", DownPath},
             {":scheme", "https"},
             {":authority", State->Host}},
            true);
        return State->DownloadStream >= 0;
    }

    inline auto StartSplitClientDriver(const std::shared_ptr<SplitClientState> &State) -> void
    {
        Net::co_spawn(
            State->Encrypted->Executor(),
            [State]() -> Net::awaitable<void>
            {
                std::array<std::byte, 16384> Buffer{};
                while (true)
                {
                    std::error_code ErrorCode;
                    const auto Read = co_await State->Encrypted->async_read_some(Buffer, ErrorCode);
                    if (ErrorCode || Read == 0 || Read > Buffer.size())
                    {
                        break;
                    }
                    if (!State->Session->Feed(
                            std::span<const std::byte>(Buffer.data(), Read), ErrorCode) &&
                        ErrorCode != make_error_code(Error::NeedMore))
                    {
                        break;
                    }
                    try
                    {
                        co_await FlushSplitClient(State);
                    }
                    catch (...)
                    {
                        break;
                    }
                }
                State->Transport->NotifyEof();
                (void)State->Response->try_send(boost::system::error_code{}, false);
            },
            Net::detached);
    }

    [[nodiscard]] inline auto WaitSplitClientResponse(
        const std::shared_ptr<SplitClientState> &State) -> Net::awaitable<SharedTransmission>
    {
        boost::system::error_code ResponseError;
        Net::steady_timer Deadline(State->Encrypted->Executor());
        Deadline.expires_after(std::chrono::seconds(30));
        auto Receive = State->Response->async_receive(
            Net::redirect_error(Net::use_awaitable, ResponseError));
        const auto Result = co_await (std::move(Receive) || Deadline.async_wait(Net::use_awaitable));
        if (Result.index() == 1 || ResponseError || !std::get<0>(Result))
        {
            CloseSplitClient(State);
            co_return nullptr;
        }
        co_return State->Transport;
    }

    [[nodiscard]] inline auto ConnectSplit(
        SharedTransmission Raw,
        Net::ssl::context &SslCtx,
        const Config &Cfg,
        std::string_view Host) -> Net::awaitable<SharedTransmission>
    {
        auto Stream = co_await ConnectTls(std::move(Raw), SslCtx, Host);
        if (!Stream || !Cfg.Enabled() || !Cfg.IsSplit())
        {
            if (Stream)
            {
                auto Recovered = Stream->next_layer().Release();
                if (Recovered)
                {
                    Recovered->Close();
                }
            }
            co_return nullptr;
        }
        auto State = MakeSplitClientState(std::move(Stream), Cfg, std::string(Host));
        if (!OpenSplitClientStreams(State))
        {
            CloseSplitClient(State);
            co_return nullptr;
        }
        StartSplitClientDriver(State);
        try
        {
            co_await FlushSplitClient(State);
        }
        catch (...)
        {
            CloseSplitClient(State);
            co_return nullptr;
        }
        co_return co_await WaitSplitClientResponse(State);
    }

    struct ClientState final
    {
        std::shared_ptr<Preview::Transport::Encrypted> Encrypted;
        SharedH2Session Session;
        std::shared_ptr<WireWriter> Wire;
        std::shared_ptr<XhttpTransport> Transport;
        std::shared_ptr<ResponseChannel> Response;
    };

    [[nodiscard]] inline auto MakeClientState(Preview::Transport::Encrypted::SharedStream Stream)
        -> std::shared_ptr<ClientState>
    {
        auto State = std::make_shared<ClientState>();
        State->Encrypted = std::make_shared<Preview::Transport::Encrypted>(std::move(Stream));
        State->Session = std::make_shared<h2::SessionImpl>(State->Encrypted->Executor(), false);
        State->Wire = std::make_shared<WireWriter>(
            State->Encrypted->Executor(),
            [Encrypted = State->Encrypted](std::span<const std::byte> Data) -> Net::awaitable<void>
            {
                std::error_code ErrorCode;
                const auto N = co_await Encrypted->AsyncWrite(Data, ErrorCode);
                if (ErrorCode || N != Data.size())
                {
                    if (ErrorCode)
                    {
                        throw std::system_error(ErrorCode);
                    }
                    throw std::system_error(std::make_error_code(std::errc::io_error));
                }
                co_return;
            });
        State->Transport = std::make_shared<XhttpTransport>(
            State->Encrypted->Executor(),
            [Session = State->Session, Wire = State->Wire](std::int32_t StreamId,
                                                             std::span<const std::byte> Data)
                -> Net::awaitable<void>
            {
                if (Session->SubmitData(StreamId, Data, false) != 0)
                {
                    throw std::system_error(std::make_error_code(std::errc::broken_pipe));
                }
                std::vector<std::byte> Out;
                if (Session->Collect(Out) && !Out.empty())
                {
                    co_await Wire->Write(Out);
                }
                co_return;
            },
            [Session = State->Session, Wire = State->Wire](std::int32_t StreamId)
                -> Net::awaitable<void>
            {
                if (Session->SubmitData(StreamId, {}, true) != 0)
                {
                    throw std::system_error(std::make_error_code(std::errc::broken_pipe));
                }
                std::vector<std::byte> Out;
                if (Session->Collect(Out) && !Out.empty())
                {
                    co_await Wire->Write(Out);
                }
                co_return;
            });
        State->Response = std::make_shared<ResponseChannel>(State->Encrypted->Executor(), 1);
        State->Session->OnHeaders = [Transport = State->Transport, Response = State->Response](
                                         std::int32_t StreamId, const h2::HeaderList &Headers, bool)
        {
            if (StreamId != Transport->StreamId_)
            {
                return;
            }
            bool StatusOk = false;
            bool ContentTypeOk = false;
            for (const auto &Header : Headers)
            {
                if (Header.Name == ":status" && Header.value == "200")
                {
                    StatusOk = true;
                }
                else if (Header.Name == "content-type" && Header.value == "text/event-stream")
                {
                    ContentTypeOk = true;
                }
            }
            (void)Response->try_send(boost::system::error_code{}, StatusOk && ContentTypeOk);
        };
        State->Session->OnData = [Transport = State->Transport](std::int32_t StreamId,
                                                                 std::span<const std::byte> Data)
        {
            if (StreamId == Transport->StreamId_)
            {
                Transport->Push(Data);
            }
        };
        State->Session->OnStreamClose = [Transport = State->Transport](std::int32_t StreamId,
                                                                         std::uint32_t)
        {
            if (StreamId == Transport->StreamId_)
            {
                Transport->NotifyEof();
            }
        };
        return State;
    }

    inline auto CloseClientState(const std::shared_ptr<ClientState> &State) -> void
    {
        State->Transport->Close();
        State->Wire->Close();
        State->Encrypted->Close();
    }

    inline auto CloseClientStream(Preview::Transport::Encrypted::SharedStream &Stream) -> void
    {
        if (!Stream)
        {
            return;
        }
        auto Recovered = Stream->next_layer().Release();
        if (Recovered)
        {
            Recovered->Cancel();
            Recovered->Close();
        }
        Stream.reset();
    }

    inline auto StartClientDriver(const std::shared_ptr<ClientState> &State) -> void
    {
        Net::co_spawn(
            State->Encrypted->Executor(),
            [State]() -> Net::awaitable<void>
            {
                std::array<std::byte, 16384> Buffer{};
                while (true)
                {
                    std::error_code ErrorCode;
                    const auto N = co_await State->Encrypted->async_read_some(Buffer, ErrorCode);
                    if (ErrorCode || N == 0)
                    {
                        break;
                    }
                    if (N > Buffer.size())
                    {
                        break;
                    }
                    if (!State->Session->Feed(
                            std::span<const std::byte>(Buffer.data(), N),
                            ErrorCode) &&
                        ErrorCode != make_error_code(Error::NeedMore))
                    {
                        break;
                    }
                    std::vector<std::byte> Out;
                    if (State->Session->Collect(Out) && !Out.empty())
                    {
                        try
                        {
                            co_await State->Wire->Write(Out);
                        }
                        catch (...)
                        {
                            break;
                        }
                    }
                }
                State->Transport->NotifyEof();
                (void)State->Response->try_send(boost::system::error_code{}, false);
                co_return;
            },
            Net::detached);
    }

    [[nodiscard]] inline auto OpenClientStream(const std::shared_ptr<ClientState> &State,
                                               const Config &Cfg, std::string_view Host) -> bool
    {
        State->Session->SendSettings();
        const auto StreamId = State->Session->OpenStream(
            {{":method", "POST"}, {":path", Cfg.Path}, {":scheme", "https"},
             {":authority", std::string(Host)}, {"content-type", "text/event-stream"}},
            false);
        if (StreamId < 0)
        {
            return false;
        }
        State->Transport->BindStream(StreamId);
        return true;
    }

    [[nodiscard]] inline auto FlushClientFrames(const std::shared_ptr<ClientState> &State)
        -> Net::awaitable<void>
    {
        std::vector<std::byte> Out;
        if (State->Session->Collect(Out) && !Out.empty())
        {
            co_await State->Wire->Write(Out);
        }
    }

    [[nodiscard]] inline auto WaitClientResponse(const std::shared_ptr<ClientState> &State)
        -> Net::awaitable<SharedTransmission>
    {
        boost::system::error_code ResponseEc;
        Net::steady_timer Deadline(State->Encrypted->Executor());
        Deadline.expires_after(std::chrono::seconds(30));
        auto Receive = State->Response->async_receive(
            Net::redirect_error(Net::use_awaitable, ResponseEc));
        const auto Result = co_await (std::move(Receive) || Deadline.async_wait(Net::use_awaitable));
        if (Result.index() == 1 || ResponseEc || !std::get<0>(Result))
        {
            CloseClientState(State);
            co_return nullptr;
        }
        co_return State->Transport;
    }

    /**
     * @brief 执行 XHTTP 客户端 stream-one 握手
     * @param Raw 底层传输（所有权转移）
     * @param SslCtx TLS 客户端上下文
     * @param Cfg XHTTP 配置
     * @param Host SNI 与 HTTP/2 authority
     * @return 已完成响应头协商的双向传输；失败返回空
     */
    [[nodiscard]] inline auto Connect(
        SharedTransmission Raw,
        Net::ssl::context &SslCtx,
        const Config &Cfg,
        std::string_view Host = {}) -> Net::awaitable<SharedTransmission>
    {
        if (Cfg.IsSplit())
        {
            co_return co_await ConnectSplit(std::move(Raw), SslCtx, Cfg, Host);
        }
        const auto ConfigValue = Cfg;
        const auto HostValue = std::string(Host);
        auto Stream = co_await ConnectTls(std::move(Raw), SslCtx, HostValue);
        if (!Stream)
        {
            co_return nullptr;
        }
        if (!ConfigValue.Enabled())
        {
            CloseClientStream(Stream);
            co_return nullptr;
        }
        auto State = MakeClientState(std::move(Stream));
        StartClientDriver(State);
        if (!OpenClientStream(State, ConfigValue, HostValue))
        {
            CloseClientState(State);
            co_return nullptr;
        }
        try
        {
            co_await FlushClientFrames(State);
        }
        catch (...)
        {
            CloseClientState(State);
            co_return nullptr;
        }
        co_return co_await WaitClientResponse(State);
    }

    /**
     * @brief 服务端 Accept 便捷入口
     * @param Raw 底层传输（所有权转移）
     * @param SslCtx TLS 服务端上下文
     * @param ConfigValue XHTTP 配置
     * @return 匹配流的双向传输；失败返回 nullptr
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Raw,
        Net::ssl::context &SslCtx,
        const Config &ConfigValue) -> Net::awaitable<SharedTransmission>
    {
        if (ConfigValue.IsSplit())
        {
            auto Handler = std::make_shared<XhttpSplitAccept>(
                std::move(Raw), SslCtx, ConfigValue);
            co_return co_await Handler->Run();
        }
        auto Handler = std::make_shared<XhttpAccept>(std::move(Raw), SslCtx, ConfigValue);
        co_return co_await Handler->Run();
    }

} // namespace Preview::Xhttp
