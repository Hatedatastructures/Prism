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

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Diagnose/Log.hpp>

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Memory/Container.hpp>

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string_view>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

namespace Preview::Http3 {

    /**
     * @struct OutPacket
     * @brief nghttp3 输出包（目标 QUIC 流 + 待发字节）
     */
    struct OutPacket
    {
        std::int64_t StreamId{0};      ///< 目标 QUIC 流
        Preview::Memory::Vector<std::byte> Data; ///< 待发字节
        explicit OutPacket(Preview::Memory::ResourcePointer mr) : Data(mr)
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
         * @param mr 内存资源
         */
        explicit AuthServer(Preview::Memory::ResourcePointer mr);

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
         * @param fin 是否为流末尾
         * @return 协议处理是否成功（失败即连接错误，应断开）
         */
        [[nodiscard]] auto Feed(std::int64_t StreamId, std::span<const std::byte> Data, bool Fin)
            -> Fault::Code;

        /**
         * @brief 收集待发数据（nghttp3 → QUIC 流）
         * @param out 输出包集合（PumpOutput 内部已向 nghttp3 登记写偏移，
         *        调用方直接写回 QUIC 即可，无需再调 AddWriteOffset）
         * @return 是否成功
         */
        [[nodiscard]] auto PumpOutput(std::vector<OutPacket> &out) -> bool;

        /**
         * @brief 告知 nghttp3 某流已写回字节数（writev_stream 输出消费确认）
         * @param StreamId 流 ID
         * @param len 已写回字节数
         */
        void AddWriteOffset(std::int64_t StreamId, std::size_t len);

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

        /**
         * @brief 提交认证成功响应（:status 233 + Hysteria-UDP/CC-RX/Padding）
         * @return 是否成功（响应字节随下次 PumpOutput 输出）
         */
        [[nodiscard]] auto SubmitAuthResponse() -> Fault::Code;

        /**
         * @brief 释放 nghttp3 连接状态
         */
        void Close();

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
        static auto CbBeginHeaders(nghttp3_conn *Conn, int64_t StreamId, void *user_data,
                                     void *stream_user_data) -> int;
        /** @brief nghttp3 回调：接收单个头字段 */
        static auto CbRecvHeader(nghttp3_conn *Conn, int64_t StreamId, int32_t token, nghttp3_rcbuf *Name,
                                   nghttp3_rcbuf *value, uint8_t Flags, void *user_data,
                                   void *stream_user_data) -> int;
        /** @brief nghttp3 回调：头字段接收完毕（end_headers） */
        static auto CbEndHeaders(nghttp3_conn *Conn, int64_t StreamId, int Fin, void *user_data,
                                   void *stream_user_data) -> int;
        /** @brief nghttp3 回调：接收请求体数据 */
        static auto CbRecvData(nghttp3_conn *Conn, int64_t StreamId, const uint8_t *Data, size_t datalen,
                                 void *user_data, void *stream_user_data) -> int;
        /** @brief nghttp3 回调：对端停止发送 */
        static auto CbStopSending(nghttp3_conn *Conn, int64_t StreamId, uint64_t app_error_code,
                                    void *user_data, void *stream_user_data) -> int;
        /** @brief nghttp3 回调：流结束（fin） */
        static auto CbEndStream(nghttp3_conn *Conn, int64_t StreamId, void *user_data,
                                  void *stream_user_data) -> int;
        /** @brief nghttp3 随机数回调（密钥材料生成） */
        static void CbRand(uint8_t *dest, size_t destlen);

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
        Preview::Memory::String Method_;         ///< :method
        Preview::Memory::String Path_;           ///< :path
        Preview::Memory::String Auth_;           ///< Hysteria-Auth 头
        std::uint64_t Rx_{0};           ///< Hysteria-CC-RX 头
    };



    namespace
    {
        /**
         * @brief 从 rcbuf 取字节视图
         * @param rc nghttp3 接收缓冲区
         * @return 缓冲区字节视图
         */
        [[nodiscard]] auto RcbufView(nghttp3_rcbuf *Rc) -> std::string_view
        {
            const auto Buf = nghttp3_rcbuf_get_buf(Rc);
            return AsStrView(std::span<const std::uint8_t>(Buf.base, Buf.len));
        }
    } // namespace

    inline AuthServer::AuthServer(const Preview::Memory::ResourcePointer mr) : Mr_(mr), Method_(mr), Path_(mr), Auth_(mr)
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

        nghttp3_callbacks callbacks{};
        callbacks.begin_headers = CbBeginHeaders;
        callbacks.recv_header = CbRecvHeader;
        callbacks.end_headers = CbEndHeaders;
        callbacks.recv_data = CbRecvData;
        callbacks.stop_sending = CbStopSending;
        callbacks.end_stream = CbEndStream;
        callbacks.rand = CbRand;

        nghttp3_settings settings{};
        nghttp3_settings_default_versioned(NGHTTP3_SETTINGS_VERSION, &settings);

        const auto Rv = nghttp3_conn_server_new_versioned(&Conn_, NGHTTP3_CALLBACKS_VERSION, &callbacks,
                                                          NGHTTP3_SETTINGS_VERSION, &settings,
                                                          nghttp3_mem_default(), this);
        if (Rv != 0)
        {
            Conn_ = nullptr;
            Diagnose::Warn("hysteria2: nghttp3_conn_server_new Failed: {}", nghttp3_strerror(Rv));
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

    inline auto AuthServer::PumpOutput(std::vector<OutPacket> &out) -> bool
    {
        if (!Conn_)
        {
            return false;
        }

        std::array<nghttp3_vec, 16> vecs{};
        std::array<std::array<std::byte, 4096>, 16> bufs{};

        for (;;)
        {
            std::int64_t StreamId = -1;
            int Fin = 0;
            for (std::size_t I = 0; I < vecs.size(); ++I)
            {
                vecs[I].base = AsU8(std::span(bufs[I])).data();
                vecs[I].len = bufs[I].size();
            }

            nghttp3_ssize sveccnt =
                nghttp3_conn_writev_stream(Conn_, &StreamId, &Fin, vecs.data(), vecs.size());
            if (sveccnt < 0)
            {
                Diagnose::Warn("hysteria2: nghttp3 writev_stream Failed: {}",
                               nghttp3_strerror(static_cast<int>(sveccnt)));
                return false;
            }
            if (sveccnt == 0)
            {
                break;
            }

            // 输出字节复制到 out 缓冲（应用保证写回 QUIC），立即告知 nghttp3 消费，
            // 否则下次 writev_stream 返回相同数据导致死循环
            OutPacket pkt(Mr_);
            pkt.StreamId = StreamId;
            for (nghttp3_ssize I = 0; I < sveccnt; ++I)
            {
                const auto Bytes = AsBytes(std::span<const std::uint8_t>(vecs[I].base, vecs[I].len));
                pkt.Data.insert(pkt.Data.end(), Bytes.begin(), Bytes.end());
            }
            const auto Nwritten = pkt.Data.size();
            out.push_back(std::move(pkt));
            nghttp3_conn_add_write_offset(Conn_, StreamId, Nwritten);

            if (Fin)
            {
                nghttp3_conn_shutdown_stream_write(Conn_, StreamId);
            }
        }
        return true;
    }

    inline void AuthServer::AddWriteOffset(const std::int64_t StreamId, const std::size_t len)
    {
        if (Conn_ && len > 0)
        {
            nghttp3_conn_add_write_offset(Conn_, StreamId, len);
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

        std::array<nghttp3_nv, 4> nva{};
        std::size_t N = 0;
        nva[N++] = nghttp3_nv{reinterpret_cast<const uint8_t *>(":status"),
                              reinterpret_cast<const uint8_t *>("233"), 7, 3, NGHTTP3_NV_FLAG_NONE};
        nva[N++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-udp"),
                              reinterpret_cast<const uint8_t *>("true"), 12, 4, NGHTTP3_NV_FLAG_NONE};
        nva[N++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-cc-rx"),
                              reinterpret_cast<const uint8_t *>("0"), 13, 1, NGHTTP3_NV_FLAG_NONE};
        nva[N++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-padding"),
                              reinterpret_cast<const uint8_t *>("0"), 15, 1, NGHTTP3_NV_FLAG_NONE};

        const auto Rv = nghttp3_conn_submit_response(Conn_, AuthStream_, nva.data(), N, nullptr);
        if (Rv != 0)
        {
            Diagnose::Warn("hysteria2: nghttp3 submit_response Failed: {}", nghttp3_strerror(Rv));
            return Fault::Code::ProtocolError;
        }
        return Fault::Code::Success;
    }

    inline void AuthServer::Close()
    {
        if (Conn_)
        {
            nghttp3_conn_del(Conn_);
            Conn_ = nullptr;
        }
    }

    inline auto AuthServer::CbBeginHeaders(nghttp3_conn *Conn, const int64_t StreamId, void *user_data,
                                  void *stream_user_data) -> int
    {
        (void)Conn;
        (void)stream_user_data;
        auto *self = static_cast<AuthServer *>(user_data);
        if (self->AuthStream_ < 0)
        {
            self->AuthStream_ = StreamId;
        }
        return 0;
    }

    inline auto AuthServer::CbRecvHeader(nghttp3_conn *Conn, const int64_t StreamId, const int32_t token,
                                nghttp3_rcbuf *Name, nghttp3_rcbuf *value, const uint8_t Flags,
                                void *user_data, void *stream_user_data) -> int
    {
        (void)Conn;
        (void)Flags;
        (void)stream_user_data;
        auto *self = static_cast<AuthServer *>(user_data);
        if (self->AuthStream_ < 0 || StreamId != self->AuthStream_)
        {
            return 0;
        }

        const auto V = RcbufView(value);
        switch (token)
        {
        case NGHTTP3_QPACK_TOKEN__METHOD: self->Method_.assign(V.data(), V.size()); return 0;
        case NGHTTP3_QPACK_TOKEN__PATH: self->Path_.assign(V.data(), V.size()); return 0;
        default: break;
        }

        const auto Nm = RcbufView(Name);
        if (Nm == "hysteria-auth")
        {
            self->Auth_.assign(V.data(), V.size());
        }
        else if (Nm == "hysteria-cc-rx")
        {
            std::from_chars(V.data(), V.data() + V.size(), self->Rx_);
        }
        return 0;
    }

    inline auto AuthServer::CbEndHeaders(nghttp3_conn *Conn, const int64_t StreamId, const int Fin, void *user_data,
                                void *stream_user_data) -> int
    {
        (void)Conn;
        (void)Fin;
        (void)stream_user_data;
        auto *self = static_cast<AuthServer *>(user_data);
        if (StreamId == self->AuthStream_)
        {
            self->HeadersDone_ = true;
        }
        return 0;
    }

    inline auto AuthServer::CbRecvData(nghttp3_conn *Conn, const int64_t StreamId, const uint8_t *Data,
                              const size_t datalen, void *user_data, void *stream_user_data) -> int
    {
        (void)Conn;
        (void)StreamId;
        (void)Data;
        (void)datalen;
        (void)user_data;
        (void)stream_user_data;
        return 0;
    }

    inline auto AuthServer::CbStopSending(nghttp3_conn *Conn, const int64_t StreamId, const uint64_t app_error_code,
                                 void *user_data, void *stream_user_data) -> int
    {
        (void)Conn;
        (void)StreamId;
        (void)app_error_code;
        (void)user_data;
        (void)stream_user_data;
        return 0;
    }

    inline auto AuthServer::CbEndStream(nghttp3_conn *Conn, const int64_t StreamId, void *user_data,
                               void *stream_user_data) -> int
    {
        (void)Conn;
        (void)StreamId;
        (void)user_data;
        (void)stream_user_data;
        return 0;
    }

    inline void AuthServer::CbRand(uint8_t *dest, const size_t destlen)
    {
        for (std::size_t I = 0; I < destlen; ++I)
        {
            dest[I] = static_cast<std::uint8_t>(std::rand());
        }
    }


} // namespace Preview::Http3
