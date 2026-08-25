/**
 * @file Conn.hpp
 * @brief VMess 客户端会话（Transmission 装饰器）
 * @details 客户端视角的完整 VMess（AEAD）实现：
 * 1. 生成随机 IV/Key/验证字节/填充与 AuthID 随机数
 * 2. 构造请求头明文 → SealAuthHeader 密封 → 发送
 *    （命令由 handshake(Target, cmd) 参数化：Tcp/udp/mux）
 * 3. 读取 18B 响应长度块 → 解密确定响应头长度 → 读取响应头密文 →
 *    OpenResponseHeader 校验验证字节回显
 * 4. 派生分块密钥（chunkKey = KDF(requestKey, requestNonce)[:16]）
 * 5. 隧道：AsyncReadSome 解密 chunk，AsyncWriteSome 分块加密发送
 * 6. UDP 数据面：目标地址固定来自指令头，chunk 即包边界
 *    （AsyncSendDatagram 一次 Seal 一块，AsyncReceiveDatagram
 *    一次 ReadChunk 一块即一个完整数据报）
 * @note 与 vmess.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Memory/Pointer.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Vmess/Codec.hpp>
#include <common/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

    /**
     * @class Client
     * @brief VMess 客户端会话
     * @details 将底层传输层包装为 VMess 客户端，持有底层传输的
     * 独占所有权。handshake(Target, cmd) 完成请求头密封发送与响应
     * 校验，成功后通过 Transmission 接口透传（加解密）隧道数据，
     * 或通过 AsyncSendDatagram / AsyncReceiveDatagram 收发
     * UDP 数据报。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /**
         * @brief 构造函数
         * @param NextLayer 已建立连接的底层传输
         * @param cfg 客户端配置
         * @details 接管底层传输所有权，调用者不应再使用原指针。
         */
        explicit Conn(std::array<std::uint8_t, 16> uuid) : uuid_(uuid)
        {
        }

        /**
         * @brief 获取关联的执行器
         * @return 底层传输的执行器
         * @details 透传底层传输的执行器，供协程调度使用。
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return next_layer_->Executor();
        }

        /**
         * @brief 异步读取（解密后明文）
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数；0 = 流结束（结束块或对端关闭）
         * @details 握手成功后：底层读取一个分块密文 → 解密 → 从内部
         * 明文缓冲拷贝给调用方。
         * @warning 未握手或已结束时返回 0 并置 ec
         */
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!handshaken_)
            {
                ec = make_error_code(Error::not_open);
                co_return 0;
            }
            if (eof_)
            {
                ec.clear();
                co_return 0;
            }
            while (PlainOff_ >= PlainRx_.size())
            {
                const auto err = co_await ReadChunk();
                if (err != Error::none)
                {
                    ec = make_error_code(err);
                    co_return 0;
                }
                if (eof_)
                {
                    ec.clear();
                    co_return 0;
                }
            }
            const auto n = std::min(Buffer.size(), PlainRx_.size() - PlainOff_);
            std::memcpy(Buffer.data(), PlainRx_.data() + PlainOff_, n);
            PlainOff_ += n;
            ec.clear();
            co_return n;
        }

        /**
         * @brief 异步写入（加密后发送，16KB 分块）
         * @param Buffer 发送缓冲区（明文）
         * @param ec 错误码输出参数
         * @return 实际写入的明文长度
         * @details VMess AEAD chunk 上限 16KB：超过时按块分片加密发送。
         * @warning 未握手时返回 0 并置 ec
         */
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!handshaken_)
            {
                ec = make_error_code(Error::not_open);
                co_return 0;
            }
            if (Buffer.empty())
            {
                ec.clear();
                co_return 0;
            }
            std::size_t Done = 0;
            // 循环外复用加密缓冲（消除每块堆分配）；16KB+ 走线程局部池（分级分配）
            auto out = mem_.template MakeBuffer<std::uint8_t>(MaxChunkLen + ChunkEncryptor::overhead);
            while (Done < Buffer.size())
            {
                const auto n = std::min(MaxChunkLen, Buffer.size() - Done);
                const auto enc = enc_->Seal(AsU8(Buffer.subspan(Done, n)), out);
                if (enc == 0)
                {
                    ec = make_error_code(Error::bad_length);
                    co_return 0;
                }
                if (co_await SendBytes(std::span<const std::uint8_t>(out.data(), enc)))
                {
                    ec = make_error_code(Error::io_error);
                    co_return 0;
                }
                Done += n;
            }
            ec.clear();
            co_return Buffer.size();
        }

        /**
         * @brief 关闭传输层
         * @details 透传关闭到底层传输，挂起的读写立即返回。
         */
        void Close() override
        {
            if (next_layer_)
            {
                next_layer_->Close();
            }
        }

        /**
         * @brief 取消未完成异步操作
         * @details 透传取消到底层传输，挂起的读立即返回 0。
         */
        void Cancel() override
        {
            if (next_layer_)
            {
                next_layer_->Cancel();
            }
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         * @return 内层传输指针
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 内层传输指针
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         * @return 底层传输共享指针（所有权转移给调用者）
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(next_layer_);
        }
        /**
         * @brief 会话是否有效（已握手且底层存在）
         * @return 有效返回 true
         */
        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return next_layer_ != nullptr && handshaken_;
        }

        /**
         * @brief 获取底层传输引用（非拥有）
         * @return 底层传输
         */
        [[nodiscard]] auto Underlying() noexcept -> SharedTransmission
        {
            return next_layer_;
        }

        /**
         * @brief 获取会话级内存竞技场
         * @return 非拥有资源指针（供握手/解析的临时分配）
         * @note 分配的对象随 Conn 存活，Conn 析构时一次性回收
         */
        [[nodiscard]] auto Arena() noexcept -> Preview::Memory::ResourcePointer
        {
            return mem_.Arena();
        }

        /**
         * @brief 执行客户端握手
         * @param Target 目标地址
         * @param cmd 命令（默认 Tcp；UDP 数据面传 Command::Udp）
         * @return 错误码
         * @details 生成随机参数 → 密封请求头（命令写入指令头）→
         * 发送 → 读取响应校验。
         * @warning 调用前必须确保 next_layer_ 已建立连接
         */
        [[nodiscard]] auto WriteHandshake(SharedTransmission upstream, const Address &Target,
                                           std::uint8_t cmd = static_cast<std::uint8_t>(Command::Tcp)) -> net::awaitable<Error>
        {
            next_layer_ = std::move(upstream);
            // 1. 生成随机参数
            std::random_device rd;
            std::array<std::uint8_t, 16> iv{};
            std::array<std::uint8_t, 16> key{};
            for (auto &b : iv)
            {
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            }
            for (auto &b : key)
            {
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            }
            const auto v = static_cast<std::uint8_t>(rd() & 0xFF);
            const auto p = static_cast<std::uint8_t>(rd() % 16);
            std::array<std::uint8_t, 4> random4{};
            for (auto &b : random4)
            {
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            }
            const auto TimeSec = std::chrono::duration_cast<std::chrono::seconds>(
                                      std::chrono::system_clock::now().time_since_epoch())
                                      .count();

            // 2. 构造请求头明文并密封
            RequestHeader hdr;
            hdr.Version = ProtocolVersion;
            hdr.Cmd = cmd;
            hdr.opt = 0x01; // ChunkStream 分块传输
            hdr.sec = Security::aes_128_gcm;
            hdr.Target = Target;
            const auto plain = BuildRequestHeader(hdr, RequestMeta{iv, key, v, p});
            const auto CmdKey = CmdKeyFromUuid(uuid_);
            const auto sealed = SealAuthHeader(CmdKey, AuthHeaderInput{plain, TimeSec, random4});
            const auto AuthId = CreateAuthId(TimeSec, random4);
            if (co_await SendBytes(sealed))
            {
                co_return Error::io_error;
            }

            // 3. 读取 18 字节响应长度块
            std::array<std::uint8_t, 18> LenEnc{};
            if (co_await RecvExact(std::span<std::uint8_t>(LenEnc)))
            {
                co_return Error::io_error;
            }

            // 4. 派生响应密钥并解密长度字段
            const auto RespBodyKey = detail::Sha256(key);
            const auto RespBodyIv = detail::Sha256(iv);
            std::array<std::uint8_t, 16> RespKey16{};
            std::memcpy(RespKey16.data(), RespBodyKey.data(), 16);
            std::array<std::uint8_t, 16> RespIv16{};
            std::memcpy(RespIv16.data(), RespBodyIv.data(), 16);
            const auto RespLenKey = Kdf(RespKey16, KdfRespLenKey);
            const auto RespLenIv = Kdf(RespIv16, KdfRespLenIv);
            std::array<std::uint8_t, 16> rlk{};
            std::memcpy(rlk.data(), RespLenKey.data(), 16);
            std::array<std::uint8_t, 12> rliv{};
            std::memcpy(rliv.data(), RespLenIv.data(), 12);
            const auto LenPlain = detail::AesGcmOpen(detail::OpenInput{rlk, rliv, LenEnc, AuthId});
            if (LenPlain.size() != 2)
            {
                co_return Error::bad_auth;
            }
            const auto RespLen = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];

            // 5. 读取响应头密文并校验验证字节
            std::vector<std::uint8_t> RespEnc(RespLen);
            if (co_await RecvExact(RespEnc))
            {
                co_return Error::io_error;
            }
            const auto RespKey = Kdf(RespKey16, KdfRespKey);
            const auto RespIv = Kdf(RespIv16, KdfRespIv);
            std::array<std::uint8_t, 16> rk{};
            std::memcpy(rk.data(), RespKey.data(), 16);
            std::array<std::uint8_t, 12> riv{};
            std::memcpy(riv.data(), RespIv.data(), 12);
            ResponseHeader rh;
            if (OpenResponseHeader(rk, RespHeaderParseInput{riv, RespEnc, AuthId}, rh) != Error::none)
            {
                co_return Error::bad_auth;
            }
            if (rh.Version != v)
            {
                co_return Error::bad_auth;
            }

            // 6. 派生分块密钥（BodyKey = KDF(request_key, request_nonce)）
            const auto BodyKey = Kdf(key, iv);
            std::array<std::uint8_t, 16> chunk_key{};
            std::memcpy(chunk_key.data(), BodyKey.data(), 16);
            std::array<std::uint8_t, 12> chunk_nonce{};
            std::memcpy(chunk_nonce.data(), iv.data(), 12);
            enc_.emplace(chunk_key, chunk_nonce);
            dec_.emplace(chunk_key, chunk_nonce);
            handshaken_ = true;
            co_return Error::none;
        }

        /**
         * @brief 发送一个 UDP 数据报（UDP 数据面，chunk 即包边界）
         * @param payload 数据报载荷
         * @return 错误码
         * @details 目标地址固定来自指令头（不随包携带）。一次调用 =
         * 加密并发送一个数据分块（长度密文 + 载荷密文），对端
         * AsyncReceiveDatagram 恰好读到该分块即完整数据报。
         * @warning 仅在 handshake() 使用 Command::Udp 后调用；数据报
         * 模式与流式模式互斥，同一会话不可混用
         */
        [[nodiscard]] auto AsyncSendDatagram(std::span<const std::uint8_t> payload) -> net::awaitable<Error>
        {
            if (!handshaken_)
            {
                co_return Error::not_open;
            }
            std::vector<std::uint8_t> out(payload.size() + ChunkEncryptor::overhead);
            const auto n = enc_->Seal(payload, out);
            if (n == 0)
            {
                co_return Error::bad_length;
            }
            const auto wire = std::span<const std::uint8_t>(out.data(), n);
            if (co_await SendBytes(wire))
            {
                co_return Error::io_error;
            }
            co_return Error::none;
        }

        /**
         * @brief 接收一个 UDP 数据报（UDP 数据面，chunk 即包边界）
         * @param payload 输出数据报载荷
         * @return 错误码
         * @details 一次调用 = 读取并解密一个数据分块，分块明文即完整
         * 数据报。读到结束块（len=0）返回 unexpected_eof。
         * @warning 仅在 handshake() 使用 Command::Udp 后调用；数据报
         * 模式与流式模式互斥，同一会话不可混用
         */
        [[nodiscard]] auto AsyncReceiveDatagram(std::vector<std::uint8_t> &payload) -> net::awaitable<Error>
        {
            if (!handshaken_)
            {
                co_return Error::not_open;
            }
            if (eof_)
            {
                co_return Error::unexpected_eof;
            }
            const auto err = co_await ReadChunk();
            if (err != Error::none)
            {
                co_return err;
            }
            if (eof_)
            {
                co_return Error::unexpected_eof;
            }
            payload.assign(PlainRx_.begin(), PlainRx_.end());
            PlainOff_ = 0;
            co_return Error::none;
        }

        /**
         * @brief 服务端握手：解析认证头 → 校验 → 发送 AEAD 响应
         * @param upstream 上游传输（所有权移交）
         * @return 错误码与解析的请求
         * @details 精确分段读取认证头（42B 前缀 → 解密长度 → 请求头
         * 密文），cmdKey 解密成功即 UUID 匹配，发送 38B 响应头并
         * 派生分块密钥。认证失败不发送响应，静默断开。
         */
        [[nodiscard]] auto ReadHandshake(SharedTransmission upstream)
            -> net::awaitable<std::pair<Error, Message>>
        {
            next_layer_ = std::move(upstream);
            Message out;
            auto err = co_await ReadRequest(out);
            if (err != Error::none)
            {
                co_return std::pair{err, Message{}};
            }

            // 命令校验（Tcp/udp/mux 合法）
            const auto cmd = static_cast<Command>(out.Cmd);
            if (cmd != Command::Tcp && cmd != Command::Udp && cmd != Command::Mux)
            {
                co_return std::pair{Error::bad_message, Message{}};
            }

            // 发送 AEAD 响应头
            err = co_await SendSuccess(out);
            if (err != Error::none)
            {
                co_return std::pair{err, Message{}};
            }

            // 派生分块密钥（BodyKey = KDF(request_key, request_nonce) 前 16 字节）
            const auto BodyKey = Kdf(out.request_key, out.request_nonce);
            std::array<std::uint8_t, 16> chunk_key{};
            std::memcpy(chunk_key.data(), BodyKey.data(), 16);
            std::array<std::uint8_t, 12> chunk_nonce{};
            std::memcpy(chunk_nonce.data(), out.request_nonce.data(), 12);
            enc_.emplace(chunk_key, chunk_nonce);
            dec_.emplace(chunk_key, chunk_nonce);
            handshaken_ = true;
            parsed_ = out;
            co_return std::pair{Error::none, std::move(out)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（ReadHandshake 成功后有效）
         */
        [[nodiscard]] auto Parsed() const -> const Message &
        {
            return parsed_;
        }

    private:
        /**
         * @brief 读取并解析认证头（服务端）
         * @param out 输出请求消息
         * @return 错误码
         * @details 分阶段精确读取：42B 前缀 → 解密长度字段 → 读取
         * 剩余密文 → 组装解析（cmdKey 解密失败即 UUID 不匹配）→
         * 显式 UUID 校验。
         */
        [[nodiscard]] auto ReadRequest(Message &out) -> net::awaitable<Error>
        {
            // 1. 读取认证头前缀（16 AuthID + 18 LenEnc + 8 Nonce = 42 字节）
            std::array<std::uint8_t, 42> Prefix{};
            if (co_await RecvExact(std::span<std::uint8_t>(Prefix)))
            {
                co_return Error::io_error;
            }

            // 2. 解密长度字段，确定请求头密文总长
            const auto CmdKey = CmdKeyFromUuid(uuid_);
            const auto AuthId = std::span<const std::uint8_t>(Prefix).first(16);
            std::memcpy(AuthId_.data(), AuthId.data(), 16); // 响应 AAD 复用
            const auto nonce8 = std::span<const std::uint8_t>(Prefix).subspan(34, 8);
            const auto LenKey = Kdf(CmdKey, KdfHeaderLenKey, AuthId, nonce8);
            const auto LenIv = Kdf(CmdKey, KdfHeaderLenIv, AuthId, nonce8);
            std::array<std::uint8_t, 16> lk{};
            std::memcpy(lk.data(), LenKey.data(), 16);
            std::array<std::uint8_t, 12> liv{};
            std::memcpy(liv.data(), LenIv.data(), 12);
            const auto LenPlain = detail::AesGcmOpen(
                detail::OpenInput{lk, liv, std::span<const std::uint8_t>(Prefix).subspan(16, 18), AuthId});
            if (LenPlain.size() != 2)
            {
                co_return Error::bad_auth;
            }
            const auto length = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];

            // 3. 读取请求头密文（length + 16 tag）
            std::vector<std::uint8_t> body_enc(length + 16);
            if (co_await RecvExact(body_enc))
            {
                co_return Error::io_error;
            }

            // 4. 组装完整认证头，复用 handshake 的 Parser 解析
            std::vector<std::uint8_t> full;
            full.reserve(Prefix.size() + body_enc.size());
            full.insert(full.end(), Prefix.begin(), Prefix.end());
            full.insert(full.end(), body_enc.begin(), body_enc.end());
            Parser p(uuid_);
            std::error_code pec;
            p.Put(boost::asio::const_buffer(full.data(), full.size()), pec);
            if (pec || !p.IsDone())
            {
                co_return Error::bad_auth;
            }

            // 5. UUID 校验（AEAD 解密成功即隐含 cmdKey 匹配，此处显式确认）
            out = p.Get();
            if (out.uuid != uuid_)
            {
                co_return Error::bad_auth;
            }
            co_return Error::none;
        }

        /**
         * @brief 发送 AEAD 响应头（38B）
         * @param req 请求消息（request_key / request_nonce / RespHeader）
         * @return 错误码
         * @details AAD = 请求的 AuthID（对齐 mihomo：客户端以自身
         * AuthID 校验响应）。
         */
        [[nodiscard]] auto SendSuccess(const Message &req) const -> net::awaitable<Error>
        {
            const auto RespBodyKey = detail::Sha256(req.request_key);
            const auto RespBodyIv = detail::Sha256(req.request_nonce);
            std::array<std::uint8_t, 16> RespKey16{};
            std::memcpy(RespKey16.data(), RespBodyKey.data(), 16);
            std::array<std::uint8_t, 16> RespIv16{};
            std::memcpy(RespIv16.data(), RespBodyIv.data(), 16);

            const std::array<std::uint8_t, 4> v_plain{req.RespHeader, 0, 0, 0};
            const auto RespKey = Kdf(RespKey16, KdfRespKey);
            const auto RespIv = Kdf(RespIv16, KdfRespIv);
            std::array<std::uint8_t, 16> rk{};
            std::memcpy(rk.data(), RespKey.data(), 16);
            std::array<std::uint8_t, 12> riv{};
            std::memcpy(riv.data(), RespIv.data(), 12);
            const auto RespEnc = SealResponseHeader(rk, RespHeaderInput{riv, v_plain, AuthId_});

            const auto RespLenKey = Kdf(RespKey16, KdfRespLenKey);
            const auto RespLenIv = Kdf(RespIv16, KdfRespLenIv);
            std::array<std::uint8_t, 16> rlk{};
            std::memcpy(rlk.data(), RespLenKey.data(), 16);
            std::array<std::uint8_t, 12> rliv{};
            std::memcpy(rliv.data(), RespLenIv.data(), 12);
            const std::array<std::uint8_t, 2> resp_LenPlain{
                static_cast<std::uint8_t>(RespEnc.size() >> 8),
                static_cast<std::uint8_t>(RespEnc.size() & 0xFF)};
            const auto LenEnc =
                detail::AesGcmSeal(detail::SealInput{rlk, rliv, resp_LenPlain, AuthId_});

            std::vector<std::uint8_t> resp;
            resp.reserve(LenEnc.size() + RespEnc.size());
            resp.insert(resp.end(), LenEnc.begin(), LenEnc.end());
            resp.insert(resp.end(), RespEnc.begin(), RespEnc.end());
            if (co_await SendBytes(resp))
            {
                co_return Error::io_error;
            }
            co_return Error::none;
        }

        /**
         * @brief 读取并解密一个数据分块（内部循环补读）
         * @return 错误码；none 且 eof_ = 结束块
         * @details 块格式：[2B 长度密文 + 16B tag][载荷密文 + 16B tag]。
         * 解密失败（tag 校验）返回 bad_auth。
         */
        [[nodiscard]] auto ReadChunk() -> net::awaitable<Error>
        {
            // 1. 读取 18 字节块头（长度密文 + 16 tag）
            std::array<std::uint8_t, 18> head{};
            if (co_await RecvExact(std::span<std::uint8_t>(head)))
            {
                co_return Error::unexpected_eof;
            }

            // 2. 解密长度字段
            auto len = dec_->OpenLen(head);
            if (!len)
            {
                co_return len.error();
            }
            if (*len == 0) // 结束块
            {
                eof_ = true;
                co_return Error::none;
            }

            // 3. 读取载荷密文（len + 16 tag）并解密
            std::vector<std::uint8_t> enc(*len + 16);
            if (co_await RecvExact(enc))
            {
                co_return Error::unexpected_eof;
            }
            typename std::template Buffer<std::uint8_t> plain =
                mem_.template MakeBuffer<std::uint8_t>(*len);
            const auto err = dec_->OpenPayload(enc, plain);
            if (err != Error::none)
            {
                co_return err;
            }

            // 4. 存入待读缓冲
            PlainRx_ = std::move(plain);
            PlainOff_ = 0;
            co_return Error::none;
        }

        /**
         * @brief 精确读取指定字节数（内部循环补读）
         * @param buf 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto RecvExact(std::span<std::uint8_t> buf) -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < buf.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->AsyncReadSome(AsBytes(buf.subspan(Done)), ec);
                if (ec || n == 0)
                {
                    co_return true;
                }
                Done += n;
            }
            co_return false;
        }

        /**
         * @brief 发送全部字节
         * @param Data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto SendBytes(std::span<const std::uint8_t> Data) const -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < Data.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->AsyncWriteSome(AsBytes(Data.subspan(Done)), ec);
                if (ec)
                {
                    co_return true;
                }
                Done += n;
            }
            co_return false;
        }

        SharedTransmission next_layer_;         ///< 底层传输（独占所有权）
        std::array<std::uint8_t, 16> AuthId_{}; ///< 请求 AuthID（响应 AAD）
        Message parsed_{};                       ///< 服务端握手解析结果
        std::array<std::uint8_t, 16> uuid_;      ///< 协议 UUID（凭据）
        std::optional<ChunkEncryptor> enc_;     ///< 分块加密器（发送侧）
        std::optional<ChunkDecryptor> dec_;     ///< 分块解密器（接收侧）
        Memory mem_;                             ///< 会话内存策略（Arena，热路径零释放分配）
        typename std::template Buffer<std::uint8_t> PlainRx_{mem_.Arena()}; ///< 解密后的明文缓冲
        std::size_t PlainOff_{0};               ///< 明文缓冲消费偏移
        bool handshaken_{false};                 ///< 握手完成标志
        bool eof_{false};                        ///< 已读到 EOF（对端关闭）
    };


    /// 流连接共享指针
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Vmess
