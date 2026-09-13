/**
 * @file Session.hpp
 * @brief Hysteria2 HTTP/3 认证会话（nghttp3 服务端封装）
 * @details 基于 nghttp3（ngtcp2 官方 HTTP/3 帧层 + QPACK 完整实现）封装
 *          服务端认证状态机：
 *          1. 创建 nghttp3 服务端连接 + 服务器控制流/QPACK 流（SETTINGS）
 *          2. 流数据喂入 nghttp3_conn_read_stream2，回调收集认证头字段
 *          3. 认证判定后提交响应（:status 233 + Hysteria 头）
 *          4. writev_stream 收集待发字节由外部写回 QUIC 流
 *          与 quic-go（mihomo 客户端）完整 HTTP/3 栈字节级兼容。
 */

#pragma once

#include <preview/Foundation/ByteSpan.hpp>
#include <preview/Foundation/Utility/Diagnose/Log.hpp>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Memory/Container.hpp>

#include <array>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <limits>
#include <span>
#include <string_view>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

namespace Preview::Http3 {

    /**
     * @struct OutPacket
     * @brief nghttp3 输出包（目标 QUIC 流 + 待发字节 + FIN）
     */
    struct OutPacket
    {
        std::int64_t StreamId{0};      ///< 目标 QUIC 流
        Preview::Memory::Vector<std::byte> Data; ///< 待发字节
        bool Fin{false}; ///< 是否随该包发送流结束标志
        explicit OutPacket(Preview::Memory::ResourcePointer MemoryResource) : Data(MemoryResource)
        {
        }
    };

    /**
     * @class AuthServer
     * @brief Hysteria2 HTTP/3 认证服务端会话
     * @details 单条 QUIC 连接一个实例；所有 nghttp3 调用必须在同一线程
     *          （quic_gateway 的 io_context 线程）串行执行。
     */
    class AuthServer : public std::enable_shared_from_this<AuthServer>
    {
    public:
        /**
         * @brief 构造函数
         * @param MemoryResource 内存资源
         */
        explicit AuthServer(Preview::Memory::ResourcePointer MemoryResource);

        /**
         * @brief 析构函数，释放 nghttp3 连接状态
         */
        ~AuthServer() noexcept;

        AuthServer(const AuthServer &) = delete;
        AuthServer &operator=(const AuthServer &) = delete;

        /**
         * @brief 初始化：创建 nghttp3 服务端连接 + 服务器控制流/QPACK 流
         * @param OpenUniStream QUIC 层开单向流回调（失败返回 -1）
         * @return 是否成功
         */
        [[nodiscard]] auto Init(std::function<std::int64_t()> OpenUniStream) -> bool;

        /**
         * @brief 喂入流数据（QUIC 流 → nghttp3）
         * @param StreamId 流 ID
         * @param Data 明文数据
         * @param Fin 是否为流末尾
         * @return 协议处理是否成功（失败即连接错误，应断开）
         */
        [[nodiscard]] auto Feed(std::int64_t StreamId, std::span<const std::byte> Data, bool Fin)
            -> Fault::Code;

        /**
         * @brief 收集待发数据（nghttp3 → QUIC 流）
     * @param Output 输出包集合（调用方写回 QUIC 后必须按实际接受字节数调用
     *        AddWriteOffset）
         * @return 是否成功
         */
        [[nodiscard]] auto PumpOutput(std::vector<OutPacket> &Output) -> bool;

        /**
         * @brief 告知 nghttp3 某流已写回字节数（writev_stream 输出消费确认）
         * @param StreamId 流 ID
         * @param Written 已写回字节数
         */
        auto AddWriteOffset(std::int64_t StreamId, std::size_t Written) -> void;

        /**
         * @brief 认证请求头是否已接收完整（end_headers 已触发）
         * @return 是否已接收完整
         */
        [[nodiscard]] auto AuthHeadersComplete() const noexcept -> bool;

        /** @brief 获取认证请求方法（:method） */
        [[nodiscard]] auto Method() const noexcept -> std::string_view;
        /** @brief 获取认证请求路径（:path） */
        [[nodiscard]] auto Path() const noexcept -> std::string_view;
        /** @brief 获取认证凭据（Hysteria-Auth 头） */
        [[nodiscard]] auto Auth() const noexcept -> std::string_view;
        /** @brief 获取客户端声明的接收速率（Hysteria-CC-RX 头） */
        [[nodiscard]] auto Rx() const noexcept -> std::uint64_t;

        /**
         * @brief 认证请求所在流 ID（首个出现 HEADERS 的 bidi 流）
         * @return 认证请求流 ID
         */
        [[nodiscard]] auto AuthStreamId() const noexcept -> std::int64_t;

        /** @brief 设置认证响应是否声明启用 QUIC DATAGRAM */
        auto SetUdpEnabled(bool Enabled) noexcept -> void
        {
            UdpEnabled_ = Enabled;
        }

        /**
         * @brief 提交认证成功响应（:status 233 + Hysteria-UDP/CC-RX/Padding）
         * @return 是否成功（响应字节随下次 PumpOutput 输出）
         */
        [[nodiscard]] auto SubmitAuthResponse() -> Fault::Code;

        /**
         * @brief 释放 nghttp3 连接状态
         */
        auto Close() -> void;

        /**
         * @brief 获取底层 nghttp3 连接指针
         * @return nghttp3_conn* 原生连接指针
         */
        [[nodiscard]] auto Native() const noexcept -> nghttp3_conn *
        {
            return Conn_;
        }

    private:
        /** @brief nghttp3 回调：流开始接收头字段 */
        static auto CbBeginHeaders(
            nghttp3_conn *Conn,
            int64_t StreamId,
            void *UserData,
            void *StreamUserData) -> int;
        /** @brief nghttp3 回调：接收单个头字段 */
        static auto CbRecvHeader(
            nghttp3_conn *Conn,
            int64_t StreamId,
            int32_t Token,
            nghttp3_rcbuf *Name,
            nghttp3_rcbuf *Value,
            uint8_t Flags,
            void *UserData,
            void *StreamUserData) -> int;
        /** @brief nghttp3 回调：头字段接收完毕（end_headers） */
        static auto CbEndHeaders(
            nghttp3_conn *Conn,
            int64_t StreamId,
            int Fin,
            void *UserData,
            void *StreamUserData) -> int;
        /** @brief nghttp3 回调：接收请求体数据 */
        static auto CbRecvData(
            nghttp3_conn *Conn,
            int64_t StreamId,
            const uint8_t *Data,
            size_t DataLength,
            void *UserData,
            void *StreamUserData) -> int;
        /** @brief nghttp3 回调：对端停止发送 */
        static auto CbStopSending(
            nghttp3_conn *Conn,
            int64_t StreamId,
            uint64_t AppErrorCode,
            void *UserData,
            void *StreamUserData) -> int;
        /** @brief nghttp3 回调：流结束（fin） */
        static auto CbEndStream(
            nghttp3_conn *Conn,
            int64_t StreamId,
            void *UserData,
            void *StreamUserData) -> int;
        /** @brief nghttp3 随机数回调（密钥材料生成） */
        static auto CbRand(std::uint8_t *Destination, std::size_t Length) -> void;

        /**
         * 当前微秒时间戳（ngtcp2/nghttp3 共用）
         */
        [[nodiscard]] static auto NowTstamp() -> std::uint64_t;

        nghttp3_conn *Conn_{nullptr};   ///< nghttp3 连接状态
        Preview::Memory::ResourcePointer Mr_{}; ///< 内存资源
        std::int64_t CtrlStream_{-1};  ///< 服务器控制流
        std::int64_t EncStream_{-1};   ///< 服务器 QPACK encoder 流
        std::int64_t DecStream_{-1};   ///< 服务器 QPACK decoder 流
        std::int64_t AuthStream_{-1};  ///< 认证请求流
        bool HeadersDone_{false};      ///< 认证头接收完整
        bool UdpEnabled_{false};        ///< 认证响应是否启用 QUIC DATAGRAM
        Preview::Memory::String Method_;         ///< :method
        Preview::Memory::String Path_;           ///< :path
        Preview::Memory::String Auth_;           ///< Hysteria-Auth 头
        std::uint64_t Rx_{0};           ///< Hysteria-CC-RX 头
        bool PendingOutput_{false};     ///< 是否存在尚未由 QUIC 确认的输出
        std::int64_t PendingStream_{-1}; ///< 尚未确认输出所属流
        std::size_t PendingBytes_{0};   ///< 尚未确认的输出字节数
        bool PendingFin_{false};        ///< 尚未确认输出是否携带 FIN
    };



    namespace
    {
        /**
         * @brief 保持 Hysteria2 认证响应流打开
         * @details 认证响应之后同一 QUIC 连接还要承载 raw stream；返回
         *          WOULDBLOCK 让 nghttp3 只发送 HEADERS，不提前提交 FIN。
         */
        inline auto HoldAuthResponseBody(nghttp3_conn *, const std::int64_t, nghttp3_vec *, const std::size_t,
                                         std::uint32_t *Flags, void *, void *) -> nghttp3_ssize
        {
            *Flags = 0;
            return NGHTTP3_ERR_WOULDBLOCK;
        }

        /**
         * @brief 从 rcbuf 取字节视图
         * @param Rc nghttp3 接收缓冲区
         * @return 缓冲区字节视图
         */
        [[nodiscard]] auto RcbufView(nghttp3_rcbuf *Rc) -> std::string_view
        {
            const auto Buf = nghttp3_rcbuf_get_buf(Rc);
            return AsStrView(std::span<const std::uint8_t>(Buf.base, Buf.len));
        }
    } // namespace

    inline AuthServer::AuthServer(const Preview::Memory::ResourcePointer MemoryResource)
        : Mr_(MemoryResource), Method_(MemoryResource), Path_(MemoryResource), Auth_(MemoryResource)
    {
    }

    inline AuthServer::~AuthServer() noexcept
    {
        Close();
    }

    inline auto AuthServer::NowTstamp() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                              std::chrono::steady_clock::now().time_since_epoch())
                                              .count());
    }

    inline auto AuthServer::Init(std::function<std::int64_t()> OpenUniStream) -> bool
    {
        if (Conn_)
        {
            return true;
        }

        nghttp3_callbacks Callbacks{};
        Callbacks.begin_headers = CbBeginHeaders;
        Callbacks.recv_header = CbRecvHeader;
        Callbacks.end_headers = CbEndHeaders;
        Callbacks.recv_data = CbRecvData;
        Callbacks.stop_sending = CbStopSending;
        Callbacks.end_stream = CbEndStream;
        Callbacks.rand = CbRand;

        nghttp3_settings Settings{};
        nghttp3_settings_default_versioned(NGHTTP3_SETTINGS_VERSION, &Settings);

        const auto Result = nghttp3_conn_server_new_versioned(&Conn_, NGHTTP3_CALLBACKS_VERSION, &Callbacks,
                                                          NGHTTP3_SETTINGS_VERSION, &Settings,
                                                          nghttp3_mem_default(), this);
        if (Result != 0)
        {
            Conn_ = nullptr;
            Diagnose::Warn("hysteria2: nghttp3_conn_server_new Failed: {}", nghttp3_strerror(Result));
            return false;
        }

        // 服务器控制流（SETTINGS）+ QPACK encoder/decoder 流
        CtrlStream_ = OpenUniStream();
        EncStream_ = OpenUniStream();
        DecStream_ = OpenUniStream();
        if (CtrlStream_ < 0 || EncStream_ < 0 || DecStream_ < 0)
        {
            Close();
            Diagnose::Warn("hysteria2: cannot Open h3 control streams");
            return false;
        }

        if (nghttp3_conn_bind_control_stream(Conn_, CtrlStream_) != 0 ||
            nghttp3_conn_bind_qpack_streams(Conn_, EncStream_, DecStream_) != 0)
        {
            Close();
            Diagnose::Warn("hysteria2: cannot Bind h3 control streams");
            return false;
        }
        return true;
    }

    inline auto AuthServer::Feed(const std::int64_t StreamId, std::span<const std::byte> Data, const bool Fin)
        -> Fault::Code
    {
        if (!Conn_)
        {
            return Fault::Code::ProtocolError;
        }

        int FinFlag = 0;
        if (Fin)
        {
            FinFlag = 1;
        }
        const auto Rc =
            nghttp3_conn_read_stream2(Conn_, StreamId, AsU8(Data).data(), Data.size(), FinFlag,
                                      NowTstamp());
        if (Rc < 0)
        {
            Diagnose::Warn("hysteria2: nghttp3 read_stream Failed: {}",
                           nghttp3_strerror(static_cast<int>(Rc)));
            return Fault::Code::ProtocolError;
        }
        return Fault::Code::Success;
    }

    inline auto AuthServer::PumpOutput(std::vector<OutPacket> &Output) -> bool
    {
        if (!Conn_)
        {
            return false;
        }

        std::array<nghttp3_vec, 16> Vectors{};
        std::array<std::array<std::byte, 4096>, 16> Buffers{};

        if (PendingOutput_)
        {
            return true;
        }

        std::int64_t StreamId = -1;
        int Fin = 0;
        for (std::size_t Index = 0; Index < Vectors.size(); ++Index)
        {
            Vectors[Index].base = AsU8(std::span(Buffers[Index])).data();
            Vectors[Index].len = Buffers[Index].size();
        }

        const auto VectorCount = nghttp3_conn_writev_stream(
            Conn_,
            &StreamId,
            &Fin,
            Vectors.data(),
            Vectors.size());
        if (VectorCount < 0)
        {
            Diagnose::Warn("hysteria2: nghttp3 writev_stream Failed: {}",
                           nghttp3_strerror(static_cast<int>(VectorCount)));
            return false;
        }
        if (static_cast<std::size_t>(VectorCount) > Vectors.size())
        {
            Diagnose::Warn("hysteria2: nghttp3 returned an invalid vector count");
            return false;
        }

        const auto VectorSize = static_cast<std::size_t>(VectorCount);
        if (VectorSize == 0)
        {
            if (StreamId < 0)
            {
                return true;
            }
            if (Fin == 0)
            {
                Diagnose::Warn("hysteria2: nghttp3 returned an empty packet without FIN");
                return false;
            }

            OutPacket Packet(Mr_);
            Packet.StreamId = StreamId;
            Packet.Fin = true;
            PendingOutput_ = true;
            PendingStream_ = StreamId;
            PendingBytes_ = 0;
            PendingFin_ = true;
            Output.push_back(std::move(Packet));
            return true;
        }
        if (StreamId < 0)
        {
            Diagnose::Warn("hysteria2: nghttp3 returned data without a stream id");
            return false;
        }

        std::size_t ByteCount = 0;
        for (std::size_t Index = 0; Index < VectorSize; ++Index)
        {
            if (Vectors[Index].len > (std::numeric_limits<std::size_t>::max)() - ByteCount)
            {
                Diagnose::Warn("hysteria2: nghttp3 output length overflow");
                return false;
            }
            ByteCount += Vectors[Index].len;
        }
        OutPacket Packet(Mr_);
        Packet.StreamId = StreamId;
        Packet.Fin = Fin != 0;
        Packet.Data.reserve(ByteCount);
        for (std::size_t Index = 0; Index < VectorSize; ++Index)
        {
            const auto Bytes = AsBytes(std::span<const std::uint8_t>(Vectors[Index].base, Vectors[Index].len));
            Packet.Data.insert(Packet.Data.end(), Bytes.begin(), Bytes.end());
        }
        PendingOutput_ = true;
        PendingStream_ = StreamId;
        PendingBytes_ = ByteCount;
        PendingFin_ = Packet.Fin;
        Output.push_back(std::move(Packet));
        return true;
    }

    inline auto AuthServer::AddWriteOffset(
        const std::int64_t StreamId,
        const std::size_t Written) -> void
    {
        if (!Conn_ || !PendingOutput_ || StreamId != PendingStream_ || Written > PendingBytes_)
        {
            return;
        }
        if (Written > 0 || PendingBytes_ == 0)
        {
            if (nghttp3_conn_add_write_offset(Conn_, StreamId, Written) != 0)
            {
                return;
            }
            PendingBytes_ -= Written;
        }
        if (PendingBytes_ == 0)
        {
            if (PendingFin_)
            {
                nghttp3_conn_shutdown_stream_write(Conn_, StreamId);
            }
            PendingOutput_ = false;
            PendingStream_ = -1;
            PendingFin_ = false;
        }
    }

    inline auto AuthServer::AuthHeadersComplete() const noexcept -> bool
    {
        return HeadersDone_;
    }

    inline auto AuthServer::Method() const noexcept -> std::string_view
    {
        return std::string_view(Method_.data(), Method_.size());
    }

    inline auto AuthServer::Path() const noexcept -> std::string_view
    {
        return std::string_view(Path_.data(), Path_.size());
    }

    inline auto AuthServer::Auth() const noexcept -> std::string_view
    {
        return std::string_view(Auth_.data(), Auth_.size());
    }

    inline auto AuthServer::Rx() const noexcept -> std::uint64_t
    {
        return Rx_;
    }

    inline auto AuthServer::AuthStreamId() const noexcept -> std::int64_t
    {
        return AuthStream_;
    }

    inline auto AuthServer::SubmitAuthResponse() -> Fault::Code
    {
        if (!Conn_ || AuthStream_ < 0)
        {
            return Fault::Code::ProtocolError;
        }

        std::array<nghttp3_nv, 4> HeaderValues{};
        std::size_t HeaderCount = 0;
        HeaderValues[HeaderCount++] = nghttp3_nv{reinterpret_cast<const uint8_t *>(":status"),
                                                 reinterpret_cast<const uint8_t *>("233"), 7, 3,
                                                 NGHTTP3_NV_FLAG_NONE};
        const char *UdpValue = "false";
        std::size_t UdpLength = 5;
        if (UdpEnabled_)
        {
            UdpValue = "true";
            UdpLength = 4;
        }
        HeaderValues[HeaderCount++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-udp"),
                                                 reinterpret_cast<const uint8_t *>(UdpValue), 12, UdpLength,
                                                 NGHTTP3_NV_FLAG_NONE};
        HeaderValues[HeaderCount++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-cc-rx"),
                                                 reinterpret_cast<const uint8_t *>("0"), 14, 1,
                                                 NGHTTP3_NV_FLAG_NONE};
        HeaderValues[HeaderCount++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-padding"),
                                                 reinterpret_cast<const uint8_t *>("256"), 16, 3,
                                                 NGHTTP3_NV_FLAG_NONE};

        const nghttp3_data_reader Reader{HoldAuthResponseBody};
        const auto Result = nghttp3_conn_submit_response(
            Conn_,
            AuthStream_,
            HeaderValues.data(),
            HeaderCount,
            &Reader);
        if (Result != 0)
        {
            Diagnose::Warn("hysteria2: nghttp3 submit_response Failed: {}", nghttp3_strerror(Result));
            return Fault::Code::ProtocolError;
        }
        return Fault::Code::Success;
    }

    inline auto AuthServer::Close() -> void
    {
        if (Conn_)
        {
            nghttp3_conn_del(Conn_);
            Conn_ = nullptr;
        }
    }

    inline auto AuthServer::CbBeginHeaders(
        nghttp3_conn *Conn,
        const std::int64_t StreamId,
        void *UserData,
        void *StreamUserData) -> int
    {
        (void)Conn;
        (void)StreamUserData;
        auto *Server = static_cast<AuthServer *>(UserData);
        if (Server->AuthStream_ < 0)
        {
            Server->AuthStream_ = StreamId;
        }
        return 0;
    }

    inline auto AuthServer::CbRecvHeader(
        nghttp3_conn *Conn,
        const std::int64_t StreamId,
        const std::int32_t Token,
        nghttp3_rcbuf *Name,
        nghttp3_rcbuf *Value,
        const std::uint8_t Flags,
        void *UserData,
        void *StreamUserData) -> int
    {
        (void)Conn;
        (void)Flags;
        (void)StreamUserData;
        auto *Server = static_cast<AuthServer *>(UserData);
        if (Server->AuthStream_ < 0 || StreamId != Server->AuthStream_)
        {
            return 0;
        }

        const auto HeaderValue = RcbufView(Value);
        switch (Token)
        {
        case NGHTTP3_QPACK_TOKEN__METHOD:
            Server->Method_.assign(HeaderValue.data(), HeaderValue.size());
            return 0;
        case NGHTTP3_QPACK_TOKEN__PATH:
            Server->Path_.assign(HeaderValue.data(), HeaderValue.size());
            return 0;
        default: break;
        }

        const auto HeaderName = RcbufView(Name);
        if (HeaderName == "hysteria-auth")
        {
            Server->Auth_.assign(HeaderValue.data(), HeaderValue.size());
        }
        else if (HeaderName == "hysteria-cc-rx")
        {
            std::from_chars(
                HeaderValue.data(),
                HeaderValue.data() + HeaderValue.size(),
                Server->Rx_);
        }
        return 0;
    }

    inline auto AuthServer::CbEndHeaders(
        nghttp3_conn *Conn,
        const std::int64_t StreamId,
        const int Fin,
        void *UserData,
        void *StreamUserData) -> int
    {
        (void)Conn;
        (void)Fin;
        (void)StreamUserData;
        auto *Server = static_cast<AuthServer *>(UserData);
        if (StreamId == Server->AuthStream_)
        {
            Server->HeadersDone_ = true;
        }
        return 0;
    }

    inline auto AuthServer::CbRecvData(
        nghttp3_conn *Conn,
        const std::int64_t StreamId,
        const std::uint8_t *Data,
        const std::size_t DataLength,
        void *UserData,
        void *StreamUserData) -> int
    {
        (void)Conn;
        (void)StreamId;
        (void)Data;
        (void)DataLength;
        (void)UserData;
        (void)StreamUserData;
        return 0;
    }

    inline auto AuthServer::CbStopSending(
        nghttp3_conn *Conn,
        const std::int64_t StreamId,
        const std::uint64_t AppErrorCode,
        void *UserData,
        void *StreamUserData) -> int
    {
        (void)Conn;
        (void)StreamId;
        (void)AppErrorCode;
        (void)UserData;
        (void)StreamUserData;
        return 0;
    }

    inline auto AuthServer::CbEndStream(
        nghttp3_conn *Conn,
        const std::int64_t StreamId,
        void *UserData,
        void *StreamUserData) -> int
    {
        (void)Conn;
        (void)StreamId;
        (void)UserData;
        (void)StreamUserData;
        return 0;
    }

    inline auto AuthServer::CbRand(
        std::uint8_t *Destination,
        const std::size_t Length) -> void
    {
        for (std::size_t Index = 0; Index < Length; ++Index)
        {
            Destination[Index] = static_cast<std::uint8_t>(std::rand());
        }
    }


} // namespace Preview::Http3
