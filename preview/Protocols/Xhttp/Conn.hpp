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

#include <preview/Foundation/Utility/Diagnose/Log.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Http2/Impl.hpp>
#include <preview/Protocols/Http2/Session.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Transport/Encrypted.hpp>
#include <preview/Protocols/Xhttp/Types.hpp>

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
#include <cstddef>
#include <deque>
#include <exception>
#include <memory>
#include <span>
#include <string>
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

            Session_->OnHeaders = [Transport = Transport_, Session = Session_, PathValue = Cfg_.Path]
                (std::int32_t StreamId, const h2::HeaderList &Headers, bool)
            {
                if (Transport->StreamId_ >= 0)
                {
                    return;
                }
                bool IsPost = false;
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
                if (IsPost && PathOk)
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
        auto Handler = std::make_shared<XhttpAccept>(std::move(Raw), SslCtx, ConfigValue);
        co_return co_await Handler->Run();
    }

} // namespace Preview::Xhttp
