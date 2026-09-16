/**
 * @file Http2.hpp
 * @brief TrustTunnel 标准 TLS + HTTP/2 CONNECT 传输
 * @details 通过 HTTP/2 CONNECT 和 Proxy-Authorization 建立长连接，
 *          DATA 帧在握手完成后暴露为 Preview::Transmission。
 *          现有 Conn.hpp 的简化 ASCII 流保持兼容，本文件提供标准外部互操作路径。
 */

#pragma once

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Http2/Impl.hpp>
#include <Preview/Protocols/Trusttunnel/Codec.hpp>
#include <Preview/Protocols/Trusttunnel/Types.hpp>
#include <Preview/Transport/Connector.hpp>
#include <Preview/Transport/Encrypted.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/ssl.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace Preview::Trusttunnel
{

    namespace Net = boost::asio;
    namespace H2 = Preview::Http2;
    using Net::experimental::awaitable_operators::operator||;

    class Http2WireWriter final : public std::enable_shared_from_this<Http2WireWriter>
    {
    public:
        using Sink = std::function<Net::awaitable<void>(std::span<const std::byte>)>;

        Http2WireWriter(Net::any_io_executor Executor, Sink WriteSink)
            : Executor_(std::move(Executor)), Sink_(std::move(WriteSink))
        {
        }

        Http2WireWriter(const Http2WireWriter &) = delete;
        auto operator=(const Http2WireWriter &) -> Http2WireWriter & = delete;

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
            auto Request = std::make_shared<WriteRequest>(Executor_, Data);
            Queue_.push_back(Request);
            Start();
            boost::system::error_code WaitError;
            auto Receive = Request->Done.async_receive(
                Net::redirect_error(Net::use_awaitable, WaitError));
            const auto Failed = co_await std::move(Receive);
            if (WaitError || Failed != 0)
            {
                throw std::system_error(std::make_error_code(std::errc::io_error));
            }
        }

        void Close()
        {
            Closed_ = true;
            while (!Queue_.empty())
            {
                auto Request = std::move(Queue_.front());
                Queue_.pop_front();
                (void)Request->Done.try_send(
                    boost::system::errc::make_error_code(boost::system::errc::not_connected), 1);
            }
        }

    private:
        using Completion = Net::experimental::channel<void(boost::system::error_code, int)>;

        struct WriteRequest
        {
            WriteRequest(Net::any_io_executor Executor, std::span<const std::byte> Bytes)
                : Data(Bytes.begin(), Bytes.end()), Done(Executor, 1)
            {
            }

            std::vector<std::byte> Data;
            Completion Done;
        };

        void Start()
        {
            if (Running_ || Closed_ || Queue_.empty())
            {
                return;
            }
            Running_ = true;
            auto Self = shared_from_this();
            Net::co_spawn(Executor_, [Self]() -> Net::awaitable<void> { co_await Self->Loop(); },
                          Net::detached);
        }

        auto Loop() -> Net::awaitable<void>
        {
            while (!Queue_.empty())
            {
                auto Request = std::move(Queue_.front());
                Queue_.pop_front();
                boost::system::error_code Error;
                try
                {
                    if (Closed_ || !Sink_)
                    {
                        Error = boost::system::errc::make_error_code(
                            boost::system::errc::not_connected);
                    }
                    else
                    {
                        co_await Sink_(Request->Data);
                    }
                }
                catch (...)
                {
                    Error = boost::system::errc::make_error_code(boost::system::errc::io_error);
                }
                int Failed = 0;
                if (Error)
                {
                    Failed = 1;
                }
                (void)Request->Done.try_send(Error, Failed);
                if (Error)
                {
                    Closed_ = true;
                    break;
                }
            }
            Running_ = false;
            co_return;
        }

        Net::any_io_executor Executor_;
        Sink Sink_;
        std::deque<std::shared_ptr<WriteRequest>> Queue_;
        bool Running_{false};
        bool Closed_{false};
    };

    class Http2Transport final : public Preview::Transmission
    {
    public:
        using WriteCb = std::function<Net::awaitable<void>(std::int32_t, std::span<const std::byte>)>;
        using FinishCb = std::function<Net::awaitable<void>(std::int32_t)>;

        Http2Transport(Net::any_io_executor Executor, WriteCb WriteFunction, FinishCb FinishFunction = {})
            : Executor_(std::move(Executor)), WriteFunction_(std::move(WriteFunction)),
              FinishFunction_(std::move(FinishFunction)),
              Notify_(Executor_, 64)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Executor_;
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            while (ReadOffset_ >= ReadCurrent_.size())
            {
                if (Closed_)
                {
                    Error = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Eof_)
                {
                    Error.clear();
                    co_return 0;
                }
                if (EofPending_ && !Notify_.ready())
                {
                    EofPending_ = false;
                    Eof_ = true;
                    Error.clear();
                    co_return 0;
                }
                boost::system::error_code ChannelError;
                auto Receive = Notify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, ChannelError));
                auto Block = co_await std::move(Receive);
                if (ChannelError)
                {
                    Error = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                if (Block.empty())
                {
                    Eof_ = true;
                    Error.clear();
                    co_return 0;
                }
                ReadCurrent_ = std::move(Block);
                ReadOffset_ = 0;
            }
            const auto Count = (std::min)(Buffer.size(), ReadCurrent_.size() - ReadOffset_);
            std::memcpy(Buffer.data(), ReadCurrent_.data() + ReadOffset_, Count);
            ReadOffset_ += Count;
            Error.clear();
            co_return Count;
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer,
                                            std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            if (Buffer.empty())
            {
                Error.clear();
                co_return 0;
            }
            if (Closed_ || Finished_ || !WriteFunction_)
            {
                Error = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (StreamId_ < 0)
            {
                PendingWrite_.insert(PendingWrite_.end(), Buffer.begin(), Buffer.end());
                Error.clear();
                co_return Buffer.size();
            }
            auto Request = std::make_shared<WriteRequest>(Executor_, StreamId_, Buffer);
            WriteQueue_.push_back(Request);
            StartWriter();
            boost::system::error_code WaitError;
            std::size_t Written = 0;
            try
            {
                auto Receive = Request->Done->async_receive(
                    Net::redirect_error(Net::use_awaitable, WaitError));
                Written = co_await std::move(Receive);
            }
            catch (...)
            {
                Error = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (WaitError)
            {
                Error = std::make_error_code(std::errc::io_error);
                co_return Written;
            }
            Error.clear();
            co_return Written;
        }

        void Close() override
        {
            Closed_ = true;
            Notify_.cancel();
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                if (Request->Done)
                {
                    (void)Request->Done->try_send(
                        boost::system::errc::make_error_code(boost::system::errc::not_connected), 0);
                }
            }
        }

        void Cancel() override
        {
            Close();
        }

        [[nodiscard]] auto Finish() -> Net::awaitable<void>
        {
            if (Closed_ || Finished_ || StreamId_ < 0 || !FinishFunction_)
            {
                throw std::system_error(std::make_error_code(std::errc::not_connected));
            }
            Finished_ = true;
            auto Request = std::make_shared<WriteRequest>(Executor_, StreamId_, std::span<const std::byte>{}, true);
            WriteQueue_.push_back(Request);
            StartWriter();
            boost::system::error_code WaitError;
            auto Receive = Request->Done->async_receive(
                Net::redirect_error(Net::use_awaitable, WaitError));
            (void)co_await std::move(Receive);
            if (WaitError)
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
            if (!Closed_ && !Eof_)
            {
                if (!Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{}))
                {
                    EofPending_ = true;
                }
            }
        }

        void BindStream(std::int32_t StreamId)
        {
            if (Closed_ || StreamId_ >= 0)
            {
                return;
            }
            StreamId_ = StreamId;
            if (!PendingWrite_.empty())
            {
                QueuePendingWrite(std::move(PendingWrite_));
            }
        }

        std::int32_t StreamId_{-1};

    private:
        using Completion = Net::experimental::channel<void(boost::system::error_code, std::size_t)>;

        struct WriteRequest
        {
            WriteRequest(Net::any_io_executor Executor, std::int32_t StreamId,
                         std::span<const std::byte> Bytes, bool EndStream = false)
                : StreamId(StreamId), Data(Bytes.begin(), Bytes.end()), EndStream(EndStream),
                  Done(std::make_shared<Completion>(Executor, 1))
            {
            }

            std::int32_t StreamId;
            std::vector<std::byte> Data;
            bool EndStream{false};
            std::shared_ptr<Completion> Done;
        };

        void QueuePendingWrite(std::vector<std::byte> Data)
        {
            if (Data.empty() || Closed_ || !WriteFunction_)
            {
                return;
            }
            auto Request = std::make_shared<WriteRequest>(Executor_, StreamId_, Data);
            Request->Done.reset();
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
            auto Self = std::static_pointer_cast<Http2Transport>(Transmission::shared_from_this());
            Net::co_spawn(
                Executor_,
                [Self]() -> Net::awaitable<void> { co_await Self->WriteLoop(); },
                Net::detached);
        }

        auto WriteLoop() -> Net::awaitable<void>
        {
            while (!WriteQueue_.empty())
            {
                auto Request = std::move(WriteQueue_.front());
                WriteQueue_.pop_front();
                boost::system::error_code Error;
                std::size_t Written = 0;
                try
                {
                    bool MissingFunction = false;
                    if (Request->EndStream)
                    {
                        MissingFunction = !FinishFunction_;
                    }
                    else
                    {
                        MissingFunction = !WriteFunction_;
                    }
                    if (Closed_ || MissingFunction)
                    {
                        Error = boost::system::errc::make_error_code(
                            boost::system::errc::not_connected);
                    }
                    else
                    {
                        if (Request->EndStream)
                        {
                            co_await FinishFunction_(Request->StreamId);
                        }
                        else
                        {
                            co_await WriteFunction_(Request->StreamId, Request->Data);
                        }
                        Written = Request->Data.size();
                    }
                }
                catch (...)
                {
                    Error = boost::system::errc::make_error_code(boost::system::errc::io_error);
                }
                if (Request->Done)
                {
                    (void)Request->Done->try_send(Error, Written);
                }
                if (Error)
                {
                    Closed_ = true;
                    break;
                }
            }
            WriterRunning_ = false;
            co_return;
        }

        Net::any_io_executor Executor_;
        WriteCb WriteFunction_;
        FinishCb FinishFunction_;
        using Channel = Net::experimental::concurrent_channel<void(boost::system::error_code,
                                                                    std::vector<std::byte>)>;
        Channel Notify_;
        std::vector<std::byte> ReadCurrent_;
        std::size_t ReadOffset_{0};
        std::vector<std::byte> PendingWrite_;
        std::deque<std::shared_ptr<WriteRequest>> WriteQueue_;
        bool WriterRunning_{false};
        bool Closed_{false};
        bool Finished_{false};
        bool Eof_{false};
        bool EofPending_{false};
    };

    using Http2ReadyChannel = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct Http2DriverParameters
    {
        std::shared_ptr<H2::SessionImpl> Session;
        std::shared_ptr<Http2WireWriter> Wire;
        std::shared_ptr<Http2Transport> Transport;
        std::shared_ptr<Preview::Transport::Encrypted> Encrypted;
        std::shared_ptr<Http2ReadyChannel> Ready;
    };

    class Http2Accept final : public std::enable_shared_from_this<Http2Accept>
    {
    public:
        Http2Accept(SharedTransmission Raw, Net::ssl::context &SslContext,
                    const ServerConfig &Config)
            : Raw_(std::move(Raw)), SslContext_(SslContext), Config_(Config)
        {
        }

        [[nodiscard]] auto Run() -> Net::awaitable<std::pair<std::string, SharedTransmission>>
        {
            if (!Raw_)
            {
                co_return std::pair{std::string{}, SharedTransmission{}};
            }
            auto [Code, Stream, Recovered] = co_await Preview::Transport::Encrypted::SslHandshake(
                std::move(Raw_), SslContext_);
            (void)Code;
            (void)Recovered;
            if (!Stream)
            {
                co_return std::pair{std::string{}, SharedTransmission{}};
            }
            auto Encrypted = std::make_shared<Preview::Transport::Encrypted>(std::move(Stream));
            auto Session = std::make_shared<H2::SessionImpl>(Encrypted->Executor(), true);
            auto Wire = MakeWire(Encrypted);
            auto Ready = std::make_shared<Http2ReadyChannel>(Encrypted->Executor(), 1);
            auto Target = std::make_shared<std::string>();
            auto Transport = std::make_shared<Http2Transport>(
                Encrypted->Executor(), [Session, Wire](std::int32_t StreamId,
                                                       std::span<const std::byte> Data)
                    -> Net::awaitable<void>
                {
                    if (Session->SubmitData(StreamId, Data, false) != 0)
                    {
                        throw std::system_error(std::make_error_code(std::errc::broken_pipe));
                    }
                    co_await Flush(Session, Wire);
                });
            Session->OnHeaders = [Transport, Session, Config = Config_, Ready, Target](
                                     std::int32_t StreamId, const H2::HeaderList &Headers, bool)
            {
                if (Transport->StreamId_ >= 0)
                {
                    return;
                }
                bool IsConnect = false;
                std::string_view Authority;
                std::string_view Authorization;
                for (const auto &Header : Headers)
                {
                    if (Header.Name == ":method" && Header.value == "CONNECT")
                    {
                        IsConnect = true;
                    }
                    else if (Header.Name == ":authority")
                    {
                        Authority = Header.value;
                    }
                    else if (Header.Name == "proxy-authorization")
                    {
                        Authorization = Header.value;
                    }
                }
                if (!IsConnect || Authority.empty() ||
                    !VerifyBasicAuth(Authorization, Config.username, Config.password))
                {
                    (void)Session->ResetStream(StreamId, 7);
                    (void)Ready->try_send(boost::system::error_code{}, false);
                    return;
                }
                *Target = std::string(Authority);
                Transport->BindStream(StreamId);
                (void)Session->SubmitHeaders(StreamId, {{":status", "200"}}, false);
                (void)Ready->try_send(boost::system::error_code{}, true);
            };
            Session->OnData = [Transport](std::int32_t StreamId, std::span<const std::byte> Data)
            {
                if (StreamId == Transport->StreamId_)
                {
                    Transport->Push(Data);
                }
            };
            Session->OnStreamClose = [Transport](std::int32_t StreamId, std::uint32_t)
            {
                if (StreamId == Transport->StreamId_)
                {
                    Transport->NotifyEof();
                }
            };
            StartDriver(Http2DriverParameters{Session, Wire, Transport, Encrypted, Ready});
            Net::steady_timer Deadline(Encrypted->Executor());
            Deadline.expires_after(std::chrono::seconds(30));
            boost::system::error_code ReadyError;
            auto Wait = Ready->async_receive(Net::redirect_error(Net::use_awaitable, ReadyError));
            auto DeadlineWait = Deadline.async_wait(Net::use_awaitable);
            const auto Result = co_await (std::move(Wait) || std::move(DeadlineWait));
            if (Result.index() == 1 || ReadyError || !std::get<0>(Result))
            {
                Transport->Close();
                Wire->Close();
                Encrypted->Close();
                co_return std::pair{std::string{}, SharedTransmission{}};
            }
            co_return std::pair{*Target, std::move(Transport)};
        }

    private:
        using SessionPtr = std::shared_ptr<H2::SessionImpl>;

        static auto MakeWire(const std::shared_ptr<Preview::Transport::Encrypted> &Encrypted)
            -> std::shared_ptr<Http2WireWriter>
        {
            return std::make_shared<Http2WireWriter>(
                Encrypted->Executor(),
                [Encrypted](std::span<const std::byte> Data) -> Net::awaitable<void>
                {
                    std::error_code Error;
                    const auto Written = co_await Encrypted->AsyncWrite(Data, Error);
                    if (Error || Written != Data.size())
                    {
                        throw std::system_error(std::make_error_code(std::errc::io_error));
                    }
                });
        }

        static auto Flush(const SessionPtr &Session, const std::shared_ptr<Http2WireWriter> &Wire)
            -> Net::awaitable<void>
        {
            std::vector<std::byte> Output;
            if (Session->Collect(Output) && !Output.empty())
            {
                co_await Wire->Write(Output);
            }
        }

        static auto StartDriver(Http2DriverParameters Parameters)
            -> void
        {
            Net::co_spawn(
                Parameters.Encrypted->Executor(),
                [Parameters = std::move(Parameters)]() -> Net::awaitable<void>
                {
                    std::array<std::byte, 16384> Buffer{};
                    while (true)
                    {
                        std::error_code IoError;
                        const auto Read = co_await Parameters.Encrypted->async_read_some(Buffer, IoError);
                        if (IoError || Read == 0)
                        {
                            break;
                        }
                        if (Read > Buffer.size())
                        {
                            break;
                        }
                        const auto ReadWindow = std::span<const std::byte>(Buffer.data(), Read);
                        if (!Parameters.Session->Feed(ReadWindow, IoError) &&
                            IoError != make_error_code(Preview::Error::NeedMore))
                        {
                            break;
                        }
                        std::vector<std::byte> Output;
                        if (Parameters.Session->Collect(Output) && !Output.empty())
                        {
                            try
                            {
                                co_await Parameters.Wire->Write(Output);
                            }
                            catch (...)
                            {
                                break;
                            }
                        }
                    }
                    Parameters.Transport->NotifyEof();
                    (void)Parameters.Ready->try_send(boost::system::error_code{}, false);
                },
                Net::detached);
        }

        SharedTransmission Raw_;
        Net::ssl::context &SslContext_;
        ServerConfig Config_;
    };

    struct Http2ConnectParameters
    {
        SharedTransmission Upstream;
        Net::ssl::context &SslContext;
        const ClientConfig &Config;
        std::string_view Target;
        std::uint16_t Port{0};
        std::string_view ServerName;
    };

    using Http2ResponseChannel = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct Http2ClientState final
    {
        std::shared_ptr<Preview::Transport::Encrypted> Encrypted;
        std::shared_ptr<H2::SessionImpl> Session;
        std::shared_ptr<Http2WireWriter> Wire;
        std::shared_ptr<Http2Transport> Transport;
        std::shared_ptr<Http2ResponseChannel> Response;
    };

    [[nodiscard]] inline auto ConnectHttp2Tls(SharedTransmission Raw, Net::ssl::context &SslContext,
                                              std::string_view ServerName)
        -> Net::awaitable<Preview::Transport::Encrypted::SharedStream>
    {
        if (!Raw)
        {
            co_return nullptr;
        }
        Preview::Transport::Connector Connector(std::move(Raw), {});
        auto Stream = std::make_shared<Preview::Transport::Encrypted::StreamType>(
            std::move(Connector), SslContext);
        if (!ServerName.empty())
        {
            const auto Name = std::string(ServerName);
            if (SSL_set_tlsext_host_name(Stream->native_handle(), Name.c_str()) != 1)
            {
                auto Recovered = Stream->next_layer().Release();
                if (Recovered)
                {
                    Recovered->Close();
                }
                co_return nullptr;
            }
        }
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
        auto Handshake = [Stream]() -> Net::awaitable<boost::system::error_code>
        {
            boost::system::error_code ErrorCode;
            co_await Stream->async_handshake(Net::ssl::stream_base::client,
                                             Net::redirect_error(Net::use_awaitable, ErrorCode));
            co_return ErrorCode;
        };
        auto DeadlineWait = Deadline.async_wait(Net::use_awaitable);
        const auto Result = co_await (Handshake() || std::move(DeadlineWait));
        if (Result.index() == 1 || std::get<0>(Result))
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

    [[nodiscard]] inline auto MakeHttp2ClientState(
        const std::shared_ptr<Preview::Transport::Encrypted> &Encrypted)
        -> std::shared_ptr<Http2ClientState>
    {
        auto State = std::make_shared<Http2ClientState>();
        State->Encrypted = Encrypted;
        State->Session = std::make_shared<H2::SessionImpl>(Encrypted->Executor(), false);
        State->Wire = std::make_shared<Http2WireWriter>(
            Encrypted->Executor(),
            [Encrypted](std::span<const std::byte> Data) -> Net::awaitable<void>
            {
                std::error_code ErrorCode;
                const auto Written = co_await Encrypted->AsyncWrite(Data, ErrorCode);
                if (ErrorCode || Written != Data.size())
                {
                    throw std::system_error(std::make_error_code(std::errc::io_error));
                }
            });
        State->Response = std::make_shared<Http2ResponseChannel>(Encrypted->Executor(), 1);
        State->Transport = std::make_shared<Http2Transport>(
            Encrypted->Executor(),
            [Session = State->Session, Wire = State->Wire](std::int32_t StreamId,
                                                             std::span<const std::byte> Data)
                -> Net::awaitable<void>
            {
                if (Session->SubmitData(StreamId, Data, false) != 0)
                {
                    throw std::system_error(std::make_error_code(std::errc::broken_pipe));
                }
                std::vector<std::byte> Output;
                if (Session->Collect(Output) && !Output.empty())
                {
                    co_await Wire->Write(Output);
                }
            },
            [Session = State->Session, Wire = State->Wire](std::int32_t StreamId)
                -> Net::awaitable<void>
            {
                if (Session->SubmitData(StreamId, {}, true) != 0)
                {
                    throw std::system_error(std::make_error_code(std::errc::broken_pipe));
                }
                std::vector<std::byte> Output;
                if (Session->Collect(Output) && !Output.empty())
                {
                    co_await Wire->Write(Output);
                }
            });
        State->Session->OnHeaders = [Transport = State->Transport, Response = State->Response](
                                         std::int32_t StreamId, const H2::HeaderList &Headers, bool)
        {
            if (StreamId != Transport->StreamId_)
            {
                return;
            }
            bool Accepted = false;
            for (const auto &Header : Headers)
            {
                if (Header.Name == ":status" && Header.value == "200")
                {
                    Accepted = true;
                }
            }
            (void)Response->try_send(boost::system::error_code{}, Accepted);
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

    inline auto StartHttp2ClientDriver(const std::shared_ptr<Http2ClientState> &State) -> void
    {
        Net::co_spawn(
            State->Encrypted->Executor(),
            [State]() -> Net::awaitable<void>
            {
                std::array<std::byte, 16384> Buffer{};
                while (true)
                {
                    std::error_code IoError;
                    const auto Read = co_await State->Encrypted->async_read_some(Buffer, IoError);
                    if (IoError || Read == 0)
                    {
                        break;
                    }
                    if (Read > Buffer.size())
                    {
                        break;
                    }
                    if (!State->Session->Feed(std::span<const std::byte>(Buffer.data(), Read), IoError) &&
                        IoError != make_error_code(Preview::Error::NeedMore))
                    {
                        break;
                    }
                    std::vector<std::byte> Output;
                    if (State->Session->Collect(Output) && !Output.empty())
                    {
                        try
                        {
                            co_await State->Wire->Write(Output);
                        }
                        catch (...)
                        {
                            break;
                        }
                    }
                }
                State->Transport->NotifyEof();
                (void)State->Response->try_send(boost::system::error_code{}, false);
            },
                Net::detached);
    }

    [[nodiscard]] inline auto FlushHttp2ClientFrames(const std::shared_ptr<Http2ClientState> &State)
        -> Net::awaitable<void>
    {
        std::vector<std::byte> Output;
        if (State->Session->Collect(Output) && !Output.empty())
        {
            co_await State->Wire->Write(Output);
        }
    }

    [[nodiscard]] inline auto ConnectHttp2(Http2ConnectParameters Parameters)
        -> Net::awaitable<std::pair<Error, SharedTransmission>>
    {
        auto Stream = co_await ConnectHttp2Tls(std::move(Parameters.Upstream), Parameters.SslContext,
                                               Parameters.ServerName);
        if (!Stream)
        {
            co_return std::pair{Error::IoError, SharedTransmission{}};
        }
        auto State = MakeHttp2ClientState(std::make_shared<Preview::Transport::Encrypted>(std::move(Stream)));
        StartHttp2ClientDriver(State);
        State->Session->SendSettings();
        const auto Authority = std::string(Parameters.Target) + ":" + std::to_string(Parameters.Port);
        const auto StreamId = State->Session->OpenStream(
            {{":method", "CONNECT"}, {":authority", Authority},
             {"proxy-authorization", BasicAuth(Parameters.Config.username, Parameters.Config.password)}},
            false);
        if (StreamId < 0)
        {
            State->Transport->Close();
            State->Wire->Close();
            State->Encrypted->Close();
            co_return std::pair{Error::ProtocolError, SharedTransmission{}};
        }
        State->Transport->BindStream(StreamId);
        try
        {
            co_await FlushHttp2ClientFrames(State);
        }
        catch (...)
        {
            State->Transport->Close();
            State->Wire->Close();
            State->Encrypted->Close();
            co_return std::pair{Error::IoError, SharedTransmission{}};
        }
        Net::steady_timer ResponseDeadline(State->Encrypted->Executor());
        ResponseDeadline.expires_after(std::chrono::seconds(30));
        boost::system::error_code ResponseError;
        auto Receive = State->Response->async_receive(
            Net::redirect_error(Net::use_awaitable, ResponseError));
        auto DeadlineWait = ResponseDeadline.async_wait(Net::use_awaitable);
        const auto ResponseResult = co_await (std::move(Receive) || std::move(DeadlineWait));
        if (ResponseResult.index() == 1 || ResponseError || !std::get<0>(ResponseResult))
        {
            State->Transport->Close();
            State->Wire->Close();
            State->Encrypted->Close();
            co_return std::pair{Error::BadAuth, SharedTransmission{}};
        }
        co_return std::pair{Error::None, std::move(State->Transport)};
    }

    [[nodiscard]] inline auto AcceptHttp2(SharedTransmission Raw, Net::ssl::context &SslContext,
                                          const ServerConfig &Config)
        -> Net::awaitable<std::tuple<Error, std::string, SharedTransmission>>
    {
        auto Handler = std::make_shared<Http2Accept>(std::move(Raw), SslContext, Config);
        auto [Target, Transport] = co_await Handler->Run();
        Error Status = Error::IoError;
        if (Transport)
        {
            Status = Error::None;
        }
        co_return std::tuple{Status, std::move(Target), std::move(Transport)};
    }

} // namespace Preview::Trusttunnel
