/**
 * @file NativeClient.hpp
 * @brief HTTP/3 nghttp3 客户端与异步 QUIC provider 的会话适配
 * @details 负责客户端 control/QPACK 流、认证 request/response 流、
 *          nghttp3 输出的短写确认以及 HTTP/3 响应头状态。
 *          所有 nghttp3 调用都在创建会话时提供的执行器上串行执行。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nghttp3/nghttp3.h>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Protocols/Http3/Server.hpp>
#include <Preview/Protocols/Quic/Native.hpp>

namespace Preview::Http3
{

    namespace Net = boost::asio;

    /**
     * @struct NativeClientSessionOptions
     * @brief HTTP/3 客户端认证会话参数
     */
    struct NativeClientSessionOptions
    {
        Net::any_io_executor Executor{};
        std::shared_ptr<Preview::Quic::Client> Connection{};
        std::string Password{};
        std::string Authority{"hysteria"};
        std::string Path{"/auth"};
        Preview::Quic::RandomSource Random{}; ///< 可注入的 nghttp3 随机源
    };

    /**
     * @class NativeClientSession
     * @brief 将原生 QUIC 客户端接入 nghttp3 HTTP/3
     * @details 会话只负责 HTTP/3 认证控制面；认证成功后，调用方可通过
     *          OpenBidirectionalStream() 创建 Hysteria2/TUIC 数据流。
     */
    class NativeClientSession final : public std::enable_shared_from_this<NativeClientSession>
    {
    public:
        explicit NativeClientSession(NativeClientSessionOptions Options)
            : Options_(std::move(Options)), Events_(Options_.Executor, 128)
        {
            Authority_ = Options_.Authority;
            Path_ = Options_.Path;
            Password_ = Options_.Password;
            Padding_.assign(256, 'a');
        }

        NativeClientSession(const NativeClientSession &) = delete;
        auto operator=(const NativeClientSession &) -> NativeClientSession & = delete;

        /**
         * @brief 启动 QUIC/HTTP3 并完成 Hysteria2 认证请求
         * @return 成功、认证失败或协议/网络错误
         */
        [[nodiscard]] auto Authenticate() -> Net::awaitable<Fault::Code>
        {
            co_await Net::dispatch(Options_.Executor, Net::use_awaitable);
            if (!Options_.Connection)
            {
                co_return Fault::Code::InvalidArgument;
            }
            Options_.Connection->Start();
            if (!co_await Options_.Connection->WaitHandshake())
            {
                co_return Fault::Code::TlsHsfail;
            }
            if (!co_await OpenInitialStreams() || !InitializeHttp3())
            {
                Close();
                co_return Fault::Code::ProtocolError;
            }

            auto Self = shared_from_this();
            Net::co_spawn(Options_.Executor,
                          [Self]() -> Net::awaitable<void> { co_await Self->AcceptLoop(); }, Net::detached);
            const auto PeerControlCode = co_await WaitForPeerControl();
            if (PeerControlCode != Fault::Code::Success)
            {
                Close();
                co_return PeerControlCode;
            }

            AuthStream_ = co_await Options_.Connection->OpenBidirectionalStream();
            if (!AuthStream_)
            {
                Close();
                co_return Fault::Code::IoError;
            }
            Streams_[AuthStream_->StreamId()] = AuthStream_;
            if (!SubmitAuthRequest())
            {
                Close();
                co_return Fault::Code::ProtocolError;
            }

            Net::co_spawn(Options_.Executor,
                          [Self]() -> Net::awaitable<void>
                          {
                              co_await Self->ReadLoop(Self->AuthStream_, false);
                          },
                          Net::detached);

            const auto InitialOutput = co_await DrainOutput();
            if (InitialOutput != Fault::Code::Success)
            {
                Close();
                co_return InitialOutput;
            }

            while (!Closed_ && !ResponseDone_)
            {
                boost::system::error_code ReceiveError;
                const auto EventValue =
                    co_await Events_.async_receive(Net::redirect_error(Net::use_awaitable, ReceiveError));
                if (ReceiveError || !EventValue)
                {
                    break;
                }
                const auto Code = co_await HandleEvent(*EventValue);
                if (Code != Fault::Code::Success)
                {
                    TerminalCode_ = Code;
                    break;
                }
            }

            if (Closed_)
            {
                co_return TerminalCode_;
            }
            if (!ResponseDone_)
            {
                Close();
                co_return Fault::Code::ProtocolError;
            }
            if (StatusCode_ != 233)
            {
                TerminalCode_ = Fault::Code::AuthFailed;
                Close();
                co_return TerminalCode_;
            }
            Authenticated_ = true;
            TerminalCode_ = Fault::Code::Success;
            co_return Fault::Code::Success;
        }

        /**
         * @brief 打开认证后的客户端双向 QUIC 流
         * @return 流提供者；未认证或连接已关闭时为空
         */
        [[nodiscard]] auto OpenBidirectionalStream() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            if (!Authenticated_ || Closed_ || !Options_.Connection)
            {
                co_return nullptr;
            }
            co_return co_await Options_.Connection->OpenBidirectionalStream();
        }

        /**
         * @brief 关闭 HTTP/3 会话和 QUIC 连接
         */
        auto Close() -> void
        {
            auto Self = shared_from_this();
            Net::dispatch(Options_.Executor, [Self = std::move(Self)]() mutable
                          { Self->CloseOnExecutor(); });
        }

        /** @brief 查询认证是否成功 */
        [[nodiscard]] auto Authenticated() const noexcept -> bool
        {
            return Authenticated_;
        }

        /** @brief QUIC 握手是否已完成 */
        [[nodiscard]] auto HandshakeReady() const noexcept -> bool
        {
            return Options_.Connection && Options_.Connection->Health().HandshakeReady;
        }

        /** @brief HTTP/3 认证协议是否已完成 */
        [[nodiscard]] auto ProtocolReady() const noexcept -> bool
        {
            return Authenticated_;
        }

        /** @brief 获取 HTTP 响应状态码 */
        [[nodiscard]] auto StatusCode() const noexcept -> int
        {
            return StatusCode_;
        }

        /** @brief 获取服务器返回的 UDP 开关值 */
        [[nodiscard]] auto UdpEnabled() const noexcept -> bool
        {
            return UdpEnabled_;
        }

    private:
        auto CloseOnExecutor() -> void
        {
            if (Closed_)
            {
                return;
            }
            Closed_ = true;
            Events_.close();
            for (auto &[StreamId, Provider] : Streams_)
            {
                (void)StreamId;
                if (Provider)
                {
                    Provider->Close();
                }
            }
            Streams_.clear();
            if (Conn_)
            {
                nghttp3_conn_del(Conn_);
                Conn_ = nullptr;
            }
            if (Options_.Connection)
            {
                Options_.Connection->Close();
            }
        }

        enum class EventType : std::uint8_t
        {
            NewStream,
            Data,
            Error,
        };

        struct Event
        {
            EventType Type{EventType::Error};
            bool Unidirectional{false};
            bool Fin{false};
            std::error_code Error{};
            Preview::Quic::SharedStreamProvider Provider{};
            std::vector<std::byte> Data;
        };

        using EventChannel =
            Net::experimental::channel<void(boost::system::error_code, std::shared_ptr<Event>)>;

        [[nodiscard]] static auto NowTstamp() -> std::uint64_t
        {
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                                  std::chrono::steady_clock::now().time_since_epoch())
                                                  .count());
        }

        [[nodiscard]] static auto RcbufView(nghttp3_rcbuf *Buffer) -> std::string_view
        {
            if (!Buffer)
            {
                return {};
            }
            const auto Bytes = nghttp3_rcbuf_get_buf(Buffer);
            return {reinterpret_cast<const char *>(Bytes.base), Bytes.len};
        }

        [[nodiscard]] static auto ReadVarint(
            std::span<const std::byte> Data,
            std::size_t &Offset,
            std::uint64_t &Value) -> bool
        {
            if (Offset >= Data.size())
            {
                return false;
            }
            const auto First = std::to_integer<std::uint8_t>(Data[Offset]);
            const auto Length = std::size_t{1U} << (First >> 6U);
            if (Offset + Length > Data.size())
            {
                return false;
            }
            Value = First & 0x3FU;
            for (std::size_t Index = 1; Index < Length; ++Index)
            {
                Value = (Value << 8U) | std::to_integer<std::uint8_t>(Data[Offset + Index]);
            }
            Offset += Length;
            return true;
        }

        [[nodiscard]] auto ControlSettingsComplete(
            std::int64_t StreamId,
            std::span<const std::byte> Data) -> bool
        {
            auto &Prefix = UnidirectionalPrefix_[StreamId];
            const auto PrefixLength = (std::min)(Prefix.size(), std::size_t{64});
            const auto CopyLength = (std::min)(Data.size(), std::size_t{64} - PrefixLength);
            Prefix.insert(Prefix.end(), Data.begin(), Data.begin() + static_cast<std::ptrdiff_t>(CopyLength));
            if (Prefix.empty() || std::to_integer<std::uint8_t>(Prefix.front()) != 0)
            {
                return false;
            }
            std::size_t Offset = 1;
            std::uint64_t FrameType = 0;
            std::uint64_t FrameLength = 0;
            if (!ReadVarint(Prefix, Offset, FrameType) || FrameType != 0x04 ||
                !ReadVarint(Prefix, Offset, FrameLength))
            {
                return false;
            }
            return FrameLength <= Prefix.size() - Offset;
        }

        [[nodiscard]] auto OpenInitialStreams() -> Net::awaitable<bool>
        {
            for (auto &Provider : Http3Streams_)
            {
                Provider = co_await Options_.Connection->OpenUnidirectionalStream();
                if (!Provider || Provider->StreamId() < 0)
                {
                    co_return false;
                }
                Streams_[Provider->StreamId()] = Provider;
            }
            co_return true;
        }

        [[nodiscard]] auto InitializeHttp3() -> bool
        {
            nghttp3_callbacks Callbacks{};
            Callbacks.begin_headers = CbBeginHeaders;
            Callbacks.recv_header = CbRecvHeader;
            Callbacks.end_headers = CbEndHeaders;
            Callbacks.recv_data = CbRecvData;
            Callbacks.end_stream = CbEndStream;
            Callbacks.stop_sending = CbStopSending;
            Callbacks.reset_stream = CbResetStream;
            Callbacks.rand = CbRand;

            nghttp3_settings Settings{};
            nghttp3_settings_default_versioned(NGHTTP3_SETTINGS_VERSION, &Settings);
            ActiveRandomOwner_ = this;
            const auto Result = nghttp3_conn_client_new_versioned(
                &Conn_, NGHTTP3_CALLBACKS_VERSION, &Callbacks, NGHTTP3_SETTINGS_VERSION, &Settings,
                nghttp3_mem_default(), this);
            ActiveRandomOwner_ = nullptr;
            if (Result != 0 || !Conn_ || RandomFailed_)
            {
                Conn_ = nullptr;
                return false;
            }
            return nghttp3_conn_bind_control_stream(Conn_, Http3Streams_[0]->StreamId()) == 0 &&
                   nghttp3_conn_bind_qpack_streams(Conn_, Http3Streams_[1]->StreamId(),
                                                   Http3Streams_[2]->StreamId()) == 0;
        }

        [[nodiscard]] auto SubmitAuthRequest() -> bool
        {
            if (!Conn_ || !AuthStream_)
            {
                return false;
            }
            const auto Make = [](const char *Name, const std::string &Value) -> nghttp3_nv
            {
                return nghttp3_nv{reinterpret_cast<const std::uint8_t *>(Name),
                                  reinterpret_cast<const std::uint8_t *>(Value.data()),
                                  std::char_traits<char>::length(Name), Value.size(), NGHTTP3_NV_FLAG_NONE};
            };
            const std::array<nghttp3_nv, 10> Headers{
                Make(":authority", Authority_), Make(":method", Method_), Make(":path", Path_),
                Make(":scheme", Scheme_), Make("hysteria-auth", Password_),
                Make("hysteria-cc-rx", Rx_), Make("hysteria-padding", Padding_),
                Make("content-length", ContentLength_), Make("accept-encoding", AcceptEncoding_),
                Make("user-agent", UserAgent_)};
            return nghttp3_conn_submit_request(Conn_, AuthStream_->StreamId(), Headers.data(), Headers.size(),
                                               nullptr, nullptr) == 0;
        }

        [[nodiscard]] auto WaitForPeerControl() -> Net::awaitable<Fault::Code>
        {
            while (!Closed_ && !PeerCriticalStreamsReady())
            {
                boost::system::error_code ReceiveError;
                const auto EventValue =
                    co_await Events_.async_receive(Net::redirect_error(Net::use_awaitable, ReceiveError));
                if (ReceiveError || !EventValue)
                {
                    co_return Fault::Code::IoError;
                }
                const auto Code = co_await HandleEvent(*EventValue);
                if (Code != Fault::Code::Success)
                {
                    co_return Code;
                }
            }
            if (PeerCriticalStreamsReady())
            {
                co_return Fault::Code::Success;
            }
            co_return Fault::Code::IoError;
        }

        [[nodiscard]] auto PeerCriticalStreamsReady() const noexcept -> bool
        {
            return PeerControlReady_;
        }

        [[nodiscard]] auto AcceptLoop() -> Net::awaitable<void>
        {
            while (!Closed_ && Options_.Connection)
            {
                auto Provider = co_await Options_.Connection->AcceptUnidirectionalStream();
                if (!Provider || Closed_)
                {
                    co_return;
                }
                auto EventValue = std::make_shared<Event>();
                EventValue->Type = EventType::NewStream;
                EventValue->Unidirectional = true;
                EventValue->Provider = std::move(Provider);
                if (!Publish(std::move(EventValue)))
                {
                    co_return;
                }
            }
        }

        [[nodiscard]] auto ReadLoop(
            const Preview::Quic::SharedStreamProvider &Provider,
            const bool Unidirectional) -> Net::awaitable<void>
        {
            std::array<std::byte, 16384> Buffer{};
            while (!Closed_ && Provider)
            {
                std::error_code Error;
                const auto Count = co_await Provider->Read(Buffer, Error);
                auto EventValue = std::make_shared<Event>();
                EventValue->Provider = Provider;
                if (Error)
                {
                    EventValue->Type = EventType::Error;
                    EventValue->Error = Error;
                    (void)Publish(std::move(EventValue));
                    co_return;
                }
                EventValue->Type = EventType::Data;
                EventValue->Unidirectional = Unidirectional;
                EventValue->Fin = Count == 0;
                EventValue->Data.assign(Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
                if (!Publish(std::move(EventValue)) || Count == 0)
                {
                    co_return;
                }
            }
        }

        [[nodiscard]] auto Publish(std::shared_ptr<Event> EventValue) -> bool
        {
            if (Closed_ || !EventValue)
            {
                return false;
            }
            return Events_.try_send(boost::system::error_code{}, std::move(EventValue));
        }

        [[nodiscard]] auto HandleEvent(const Event &EventValue) -> Net::awaitable<Fault::Code>
        {
            if (EventValue.Type == EventType::NewStream)
            {
                co_return co_await HandleNewStream(EventValue);
            }
            if (EventValue.Type == EventType::Error)
            {
                co_return Fault::Code::IoError;
            }
            if (!EventValue.Provider || !Conn_)
            {
                co_return Fault::Code::ProtocolError;
            }
            const auto *Data = static_cast<const std::uint8_t *>(nullptr);
            if (!EventValue.Data.empty())
            {
                Data = reinterpret_cast<const std::uint8_t *>(EventValue.Data.data());
            }
            const auto Result = nghttp3_conn_read_stream2(Conn_, EventValue.Provider->StreamId(), Data,
                                                           EventValue.Data.size(), EventValue.Fin, NowTstamp());
            if (Result < 0)
            {
                co_return Fault::Code::ProtocolError;
            }
            if (EventValue.Unidirectional && !EventValue.Data.empty())
            {
                switch (std::to_integer<std::uint8_t>(EventValue.Data.front()))
                {
                case 0:
                    PeerControlReady_ =
                        ControlSettingsComplete(EventValue.Provider->StreamId(), EventValue.Data);
                    break;
                default: break;
                }
            }
            co_return co_await DrainOutput();
        }

        [[nodiscard]] auto HandleNewStream(const Event &EventValue) -> Net::awaitable<Fault::Code>
        {
            if (!EventValue.Provider || !EventValue.Unidirectional)
            {
                co_return Fault::Code::ProtocolError;
            }
            const auto StreamId = EventValue.Provider->StreamId();
            if (Streams_.contains(StreamId))
            {
                co_return Fault::Code::ProtocolError;
            }
            Streams_[StreamId] = EventValue.Provider;
            auto Self = shared_from_this();
            Net::co_spawn(Options_.Executor,
                          [Self, Provider = EventValue.Provider]() -> Net::awaitable<void>
                          { co_await Self->ReadLoop(Provider, true); },
                          Net::detached);
            co_return Fault::Code::Success;
        }

        [[nodiscard]] auto DrainOutput() -> Net::awaitable<Fault::Code>
        {
            while (!Closed_ && Conn_)
            {
                std::array<nghttp3_vec, 16> Vectors{};
                std::array<std::array<std::byte, 4096>, 16> Buffers{};
                for (std::size_t Index = 0; Index < Vectors.size(); ++Index)
                {
                    Vectors[Index].base = reinterpret_cast<std::uint8_t *>(Buffers[Index].data());
                    Vectors[Index].len = Buffers[Index].size();
                }
                std::int64_t StreamId = -1;
                int Fin = 0;
                const auto Count = nghttp3_conn_writev_stream(Conn_, &StreamId, &Fin, Vectors.data(), Vectors.size());
                if (Count < 0 || static_cast<std::size_t>(Count) > Vectors.size())
                {
                    co_return Fault::Code::ProtocolError;
                }
                if (Count == 0)
                {
                    if (StreamId < 0)
                    {
                        co_return Fault::Code::Success;
                    }
                    const auto StreamIterator = Streams_.find(StreamId);
                    if (StreamIterator == Streams_.end() || !StreamIterator->second || Fin == 0)
                    {
                        co_return Fault::Code::ProtocolError;
                    }
                    nghttp3_conn_add_write_offset(Conn_, StreamId, 0);
                    StreamIterator->second->ShutdownWrite();
                    continue;
                }
                if (StreamId < 0)
                {
                    co_return Fault::Code::ProtocolError;
                }
                const auto StreamIterator = Streams_.find(StreamId);
                if (StreamIterator == Streams_.end() || !StreamIterator->second)
                {
                    co_return Fault::Code::ProtocolError;
                }
                std::vector<std::byte> Data;
                std::size_t Total = 0;
                for (std::size_t Index = 0; Index < static_cast<std::size_t>(Count); ++Index)
                {
                    if (Vectors[Index].len > (std::numeric_limits<std::size_t>::max)() - Total)
                    {
                        co_return Fault::Code::OversizedMsg;
                    }
                    Total += Vectors[Index].len;
                }
                Data.reserve(Total);
                for (std::size_t Index = 0; Index < static_cast<std::size_t>(Count); ++Index)
                {
                    const auto *Begin = reinterpret_cast<const std::byte *>(Vectors[Index].base);
                    Data.insert(Data.end(), Begin, Begin + static_cast<std::ptrdiff_t>(Vectors[Index].len));
                }
                std::size_t Offset = 0;
                while (Offset < Data.size())
                {
                    std::error_code Error;
                    const auto Written = co_await StreamIterator->second->Write(
                        std::span<const std::byte>(Data).subspan(Offset),
                        Error);
                    if (Error || Written == 0 || Written > Data.size() - Offset)
                    {
                        co_return Fault::Code::IoError;
                    }
                    Offset += Written;
                    if (nghttp3_conn_add_write_offset(Conn_, StreamId, Written) != 0)
                    {
                        co_return Fault::Code::ProtocolError;
                    }
                }
                if (Fin != 0)
                {
                    nghttp3_conn_shutdown_stream_write(Conn_, StreamId);
                    StreamIterator->second->ShutdownWrite();
                }
            }
            co_return Fault::Code::Canceled;
        }

        static auto CbBeginHeaders(nghttp3_conn *, std::int64_t, void *, void *) -> int
        {
            return 0;
        }

        static auto CbRecvHeader(nghttp3_conn *, std::int64_t StreamId, std::int32_t Token,
                                 nghttp3_rcbuf *Name, nghttp3_rcbuf *Value, std::uint8_t,
                                 void *UserData, void *) -> int
        {
            auto *Self = static_cast<NativeClientSession *>(UserData);
            if (!Self || !Self->AuthStream_ || StreamId != Self->AuthStream_->StreamId())
            {
                return 0;
            }
            const auto Text = RcbufView(Value);
            if (Token == NGHTTP3_QPACK_TOKEN__STATUS)
            {
                std::uint32_t Status = 0;
                const auto [End, Error] = std::from_chars(Text.data(), Text.data() + Text.size(), Status);
                if (Error == std::errc{} && End == Text.data() + Text.size() && Status <= 999)
                {
                    Self->StatusCode_ = static_cast<int>(Status);
                }
            }
            else
            {
                const auto HeaderName = RcbufView(Name);
                if (HeaderName == "hysteria-udp")
                {
                    Self->UdpEnabled_ = Text == "true";
                }
            }
            return 0;
        }

        static auto CbEndHeaders(nghttp3_conn *, std::int64_t StreamId, int, void *UserData, void *) -> int
        {
            auto *Self = static_cast<NativeClientSession *>(UserData);
            if (Self && Self->AuthStream_ && StreamId == Self->AuthStream_->StreamId())
            {
                Self->HeadersDone_ = true;
            }
            return 0;
        }

        static auto CbRecvData(nghttp3_conn *, std::int64_t, const std::uint8_t *, std::size_t, void *, void *) -> int
        {
            return 0;
        }

        static auto CbEndStream(nghttp3_conn *, std::int64_t StreamId, void *UserData, void *) -> int
        {
            auto *Self = static_cast<NativeClientSession *>(UserData);
            if (Self && Self->AuthStream_ && StreamId == Self->AuthStream_->StreamId())
            {
                Self->ResponseDone_ = true;
            }
            return 0;
        }

        static auto CbStopSending(nghttp3_conn *, std::int64_t, std::uint64_t, void *, void *) -> int
        {
            return 0;
        }

        static auto CbResetStream(nghttp3_conn *, std::int64_t, std::uint64_t, void *, void *) -> int
        {
            return 0;
        }

        static auto CbRand(std::uint8_t *Destination, std::size_t Length) -> void
        {
            if (Length == 0)
            {
                return;
            }
            auto *Owner = ActiveRandomOwner_;
            int Result = 0;
            if (Owner && Owner->Options_.Random)
            {
                Result = Owner->Options_.Random(Destination, static_cast<int>(Length));
            }
            else
            {
                Result = RAND_bytes(Destination, static_cast<int>(Length));
            }
            if (Result == 1)
            {
                return;
            }
            std::fill_n(Destination, Length, std::uint8_t{0});
            if (Owner)
            {
                Owner->RandomFailed_ = true;
            }
        }

        NativeClientSessionOptions Options_;
        std::string Method_{"POST"};
        std::string Scheme_{"https"};
        std::string Authority_;
        std::string Path_;
        std::string Password_;
        std::string Rx_{"0"};
        std::string Padding_;
        std::string ContentLength_{"0"};
        std::string AcceptEncoding_{"gzip"};
        std::string UserAgent_{"Go-http-client/3.0"};
        EventChannel Events_;
        nghttp3_conn *Conn_{nullptr};
        bool RandomFailed_{false};
        inline static thread_local NativeClientSession *ActiveRandomOwner_{nullptr};
        std::array<Preview::Quic::SharedStreamProvider, 3> Http3Streams_{};
        Preview::Quic::SharedStreamProvider AuthStream_{};
        std::unordered_map<std::int64_t, Preview::Quic::SharedStreamProvider> Streams_;
        std::unordered_map<std::int64_t, std::vector<std::byte>> UnidirectionalPrefix_;
        int StatusCode_{0};
        bool UdpEnabled_{false};
        bool HeadersDone_{false};
        bool ResponseDone_{false};
        bool PeerControlReady_{false};
        bool Authenticated_{false};
        bool Closed_{false};
        Fault::Code TerminalCode_{Fault::Code::Canceled};
    };

} // namespace Preview::Http3
