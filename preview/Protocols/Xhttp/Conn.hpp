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
#include <boost/asio/ssl.hpp>

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

    namespace net = boost::asio;
    namespace h2 = Preview::Http2;

    /// h2 会话共享指针
    using SharedH2Session = std::shared_ptr<h2::SessionImpl>;

    /**
     * @class WireWriter
     * @brief XHTTP 底层字节串行写入器
     * @details driver、响应头和数据回调共享一个实例，所有写入先排队，
     *          sink 通过 Transmission::AsyncWrite 完整消费字节。
     */
    class WireWriter final : public std::enable_shared_from_this<WireWriter>
    {
    public:
        using Sink = std::function<net::awaitable<void>(std::span<const std::byte>)>;

        WireWriter(net::any_io_executor ex, Sink sink)
            : Ex_(std::move(ex)), Sink_(std::move(sink))
        {
        }

        WireWriter(const WireWriter &) = delete;
        auto operator=(const WireWriter &) -> WireWriter & = delete;

        [[nodiscard]] auto Write(std::span<const std::byte> Data) -> net::awaitable<void>
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
                net::redirect_error(net::use_awaitable, WaitEc));
            if (WaitEc || Failed != 0)
            {
                const auto Value = WaitEc ? WaitEc.value() : static_cast<int>(std::errc::io_error);
                throw std::system_error(Value, std::system_category());
            }
        }

        void Close()
        {
            Closed_ = true;
            FailQueued(boost::system::errc::make_error_code(boost::system::errc::not_connected));
        }

    private:
        using Completion = net::experimental::channel<void(boost::system::error_code, int)>;

        struct RequestState
        {
            RequestState(net::any_io_executor ex, std::span<const std::byte> Data)
                : Data(Data.begin(), Data.end()), Done(ex, 1)
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
            net::co_spawn(Ex_, [Self]() -> net::awaitable<void> { co_await Self->Loop(); }, net::detached);
        }

        void FailQueued(boost::system::error_code Ec)
        {
            while (!Queue_.empty())
            {
                auto Request = std::move(Queue_.front());
                Queue_.pop_front();
                (void)Request->Done.try_send(Ec, Ec ? 1 : 0);
            }
        }

        [[nodiscard]] auto IoError() const -> boost::system::error_code
        {
            return boost::system::errc::make_error_code(boost::system::errc::io_error);
        }

        auto Loop() -> net::awaitable<void>
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

                (void)Request->Done.try_send(Ec, Ec ? 1 : 0);
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

        net::any_io_executor Ex_;
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
        using WriteCb = std::function<net::awaitable<void>(std::int32_t StreamId,
                                                            std::span<const std::byte>)>;

        /**
         * @brief 构造
         * @param ex 执行器
         * @param WriteFn 写回调（提交 DATA 帧）
         */
        explicit XhttpTransport(net::any_io_executor ex, WriteCb WriteFn)
            : Ex_(std::move(ex)), WriteFn_(std::move(WriteFn)), Notify_(Ex_, 64)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Ex_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            while (RxOffset_ >= RxCurrent_.size())
            {
                if (Closed_)
                {
                    ec = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Eof_)
                {
                    ec = make_error_code(Error::UnexpectedEof);
                    co_return 0;
                }
                if (EofPending_ && !Notify_.ready())
                {
                    EofPending_ = false;
                    Eof_ = true;
                    ec.clear();
                    co_return 0;
                }
                boost::system::error_code ChEc;
                auto Block = co_await Notify_.async_receive(
                    net::redirect_error(net::use_awaitable, ChEc));
                if (ChEc)
                {
                    ec = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Block.empty())
                {
                    Eof_ = true;
                    ec.clear();
                    co_return 0;
                }
                RxCurrent_ = std::move(Block);
                RxOffset_ = 0;
            }
            const auto N = std::min(Buffer.size(), RxCurrent_.size() - RxOffset_);
            std::memcpy(Buffer.data(), RxCurrent_.data() + RxOffset_, N);
            RxOffset_ += N;
            ec.clear();
            co_return N;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (Buffer.empty())
            {
                ec.clear();
                co_return 0;
            }
            if (Closed_ || !WriteFn_)
            {
                ec = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (StreamId_ < 0)
            {
                // 流未匹配：缓冲写
                WritePending_.insert(WritePending_.end(), Buffer.begin(), Buffer.end());
                ec.clear();
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
                    net::redirect_error(net::use_awaitable, WaitEc));
            }
            catch (...)
            {
                ec = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (WaitEc)
            {
                ec = std::make_error_code(std::errc::io_error);
                co_return Written;
            }
            ec.clear();
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
        using CompletionChannel = net::experimental::channel<void(boost::system::error_code, std::size_t)>;

        struct WriteRequest
        {
            WriteRequest(net::any_io_executor ex, std::int32_t StreamId,
                         std::span<const std::byte> Data)
                : StreamId(StreamId), Data(Data.begin(), Data.end()),
                  Done(std::make_shared<CompletionChannel>(ex, 1))
            {
            }

            std::int32_t StreamId;
            std::vector<std::byte> Data;
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
            net::co_spawn(Ex_, [Self]() -> net::awaitable<void> { co_await Self->WriteLoop(); }, net::detached);
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

        auto WriteLoop() -> net::awaitable<void>
        {
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                boost::system::error_code WriteEc;
                std::size_t Written = 0;
                try
                {
                    if (!Closed_ && WriteFn_)
                    {
                        co_await WriteFn_(Request->StreamId, std::span<const std::byte>(Request->Data));
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
            net::experimental::concurrent_channel<void(boost::system::error_code, std::vector<std::byte>)>;

        net::any_io_executor Ex_;
        WriteCb WriteFn_;
        ChannelType Notify_;
        std::vector<std::byte> RxCurrent_;
        std::size_t RxOffset_{0};
        std::vector<std::byte> WritePending_; ///< 匹配前的写缓冲
        std::deque<std::shared_ptr<WriteRequest>> WriteQueue_;
        bool WriterRunning_{false};
        bool Closed_{false};
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
         * @param raw 底层传输（所有权转移）
         * @param SslCtx TLS 服务端上下文
         * @param cfg xhttp 配置
         */
        XhttpAccept(SharedTransmission raw, net::ssl::context &SslCtx, const Config &cfg)
            : Raw_(std::move(raw)), SslCtx_(SslCtx), Cfg_(cfg)
        {
        }

        /**
         * @brief 执行握手并等待流匹配
         * @return 匹配流的双向传输；失败返回 nullptr
         */
        [[nodiscard]] auto Run() -> net::awaitable<SharedTransmission>
        {
            if (!Raw_)
            {
                co_return nullptr;
            }
            auto [Code, Stream, recovered] =
                co_await Preview::Transport::Encrypted::SslHandshake(std::move(Raw_), SslCtx_);
            (void)Code;
            (void)recovered;
            if (!Stream)
            {
                co_return nullptr;
            }
            Encrypted_ = std::make_shared<Preview::Transport::Encrypted>(std::move(Stream));

            Session_ = std::make_shared<h2::SessionImpl>(Encrypted_->Executor(), true);
            auto Wire = std::make_shared<WireWriter>(
                Encrypted_->Executor(),
                [Encrypted = Encrypted_](std::span<const std::byte> Data) -> net::awaitable<void>
                {
                    std::error_code ec;
                    const auto N = co_await Encrypted->AsyncWrite(Data, ec);
                    if (ec || N != Data.size())
                    {
                        throw std::system_error(ec ? ec : std::make_error_code(std::errc::io_error));
                    }
                    co_return;
                });

            // 写回调捕获共享状态，所有物理写入经过同一串行器。
            auto Session = Session_;
            Transport_ = std::make_shared<XhttpTransport>(
                Encrypted_->Executor(),
                [Session, Wire](std::int32_t sid, std::span<const std::byte> Data)
                    -> net::awaitable<void>
                {
                    (void)Session->SubmitData(sid, Data, false);
                    std::vector<std::byte> out;
                    if (Session->Collect(out) && !out.empty())
                    {
                        co_await Wire->Write(out);
                    }
                    co_return;
                });

            Session_->OnHeaders = [Transport = Transport_, Session = Session_, path_cfg = Cfg_.Path]
                (std::int32_t sid, const h2::HeaderList &headers, bool)
            {
                if (Transport->StreamId_ >= 0)
                {
                    return;
                }
                bool IsPost = false;
                std::string_view Path;
                for (const auto &h : headers)
                {
                    if (h.Name == ":Method" && h.value == "POST")
                    {
                        IsPost = true;
                    }
                    else if (h.Name == ":Path")
                    {
                        Path = h.value;
                    }
                }
                const std::string_view base(path_cfg.data(), path_cfg.size());
                bool PathOk;
                if (base == "/")
                {
                    PathOk = Path.rfind('/', 0) == 0;
                }
                else
                {
                    PathOk = Path.rfind(base, 0) == 0;
                }
                if (IsPost && PathOk)
                {
                    Transport->BindStream(sid);
                    h2::HeaderList resp = {{":status", "200"}, {"content-Type", "text/event-Stream"}};
                    Session->SubmitHeaders(sid, resp, false);
                }
            };
            Session_->OnData = [Transport = Transport_](std::int32_t sid, std::span<const std::byte> Data)
            {
                if (sid == Transport->StreamId_)
                {
                    Transport->Push(Data);
                }
            };
            Session_->OnStreamClose = [Transport = Transport_](std::int32_t sid, std::uint32_t)
            {
                if (sid == Transport->StreamId_)
                {
                    Transport->NotifyEof();
                }
            };

            // driver 与数据回调共享同一个物理写入器。
            auto Transport = Transport_;
            net::co_spawn(Encrypted_->Executor(),
                          [Session, Wire, Transport, Encrypted = Encrypted_]() mutable -> net::awaitable<void>
                          {
                              std::array<std::byte, 16384> buf{};
                              while (true)
                              {
                                  std::error_code ec;
                                  const auto N = co_await Encrypted->async_read_some(buf, ec);
                                  if (ec || N == 0)
                                  {
                                      break;
                                  }
                                  if (!Session->Feed(std::span<const std::byte>(buf.data(), N), ec))
                                  {
                                      break;
                                  }
                                  std::vector<std::byte> out;
                                  if (Session->Collect(out) && !out.empty())
                                  {
                                      try
                                      {
                                          co_await Wire->Write(out);
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
                          net::detached);
            co_return Transport_;
        }

    private:
        SharedTransmission Raw_;
        net::ssl::context &SslCtx_;
        Config Cfg_;
        Preview::SharedTransmission Encrypted_;
        SharedH2Session Session_;
        std::shared_ptr<XhttpTransport> Transport_;
    };

    /**
     * @brief 服务端 Accept 便捷入口
     * @param raw 底层传输（所有权转移）
     * @param SslCtx TLS 服务端上下文
     * @param cfg xhttp 配置
     * @return 匹配流的双向传输；失败返回 nullptr
     */
    [[nodiscard]] inline auto Accept(SharedTransmission raw, net::ssl::context &SslCtx,
                                     const Config &cfg) -> net::awaitable<SharedTransmission>
    {
        auto Handler = std::make_shared<XhttpAccept>(std::move(raw), SslCtx, cfg);
        co_return co_await Handler->Run();
    }

} // namespace Preview::Xhttp
