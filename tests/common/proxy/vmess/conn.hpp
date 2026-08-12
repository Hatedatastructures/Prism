/**
 * @file conn.hpp
 * @brief VMess 客户端会话（transmission 装饰器）
 * @details 客户端视角的完整 VMess（AEAD）实现：
 * 1. 生成随机 IV/Key/验证字节/填充与 AuthID 随机数
 * 2. 构造请求头明文 → seal_auth_header 密封 → 发送
 *    （命令由 handshake(target, cmd) 参数化：tcp/udp/mux）
 * 3. 读取 18B 响应长度块 → 解密确定响应头长度 → 读取响应头密文 →
 *    open_response_header 校验验证字节回显
 * 4. 派生分块密钥（chunkKey = KDF(requestKey, requestNonce)[:16]）
 * 5. 隧道：async_read_some 解密 chunk，async_write_some 分块加密发送
 * 6. UDP 数据面：目标地址固定来自指令头，chunk 即包边界
 *    （async_send_datagram 一次 seal 一块，async_receive_datagram
 *    一次 read_chunk 一块即一个完整数据报）
 * @note 与 vmess.hpp 工厂配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/proxy/vmess/codec.hpp>
#include <common/proxy/vmess/types.hpp>

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

namespace psmtest::vmess
{


    /**
     * @class client
     * @brief VMess 客户端会话
     * @details 将底层传输层包装为 VMess 客户端，持有底层传输的
     * 独占所有权。handshake(target, cmd) 完成请求头密封发送与响应
     * 校验，成功后通过 transmission 接口透传（加解密）隧道数据，
     * 或通过 async_send_datagram / async_receive_datagram 收发
     * UDP 数据报。
     */
    class conn : public psmtest::transmission,
                 public std::enable_shared_from_this<conn>
    {
    public:
        /**
         * @brief 构造函数
         * @param next_layer 已建立连接的底层传输
         * @param cfg 客户端配置
         * @details 接管底层传输所有权，调用者不应再使用原指针。
         */
        explicit conn(std::array<std::uint8_t, 16> uuid)
            : uuid_(uuid)
        {
        }

        /**
         * @brief 获取关联的执行器
         * @return 底层传输的执行器
         * @details 透传底层传输的执行器，供协程调度使用。
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return next_layer_->executor();
        }

        /**
         * @brief 异步读取（解密后明文）
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数；0 = 流结束（结束块或对端关闭）
         * @details 握手成功后：底层读取一个分块密文 → 解密 → 从内部
         * 明文缓冲拷贝给调用方。
         * @warning 未握手或已结束时返回 0 并置 ec
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!handshaken_)
            {
                ec = make_error_code(error::not_open);
                co_return 0;
            }
            if (eof_)
            {
                ec.clear();
                co_return 0;
            }
            while (plain_off_ >= plain_rx_.size())
            {
                const auto err = co_await read_chunk();
                if (err != error::none)
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
            const auto n = std::min(buffer.size(), plain_rx_.size() - plain_off_);
            std::memcpy(buffer.data(), plain_rx_.data() + plain_off_, n);
            plain_off_ += n;
            ec.clear();
            co_return n;
        }

        /**
         * @brief 异步写入（加密后发送，16KB 分块）
         * @param buffer 发送缓冲区（明文）
         * @param ec 错误码输出参数
         * @return 实际写入的明文长度
         * @details VMess AEAD chunk 上限 16KB：超过时按块分片加密发送。
         * @warning 未握手时返回 0 并置 ec
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!handshaken_)
            {
                ec = make_error_code(error::not_open);
                co_return 0;
            }
            if (buffer.empty())
            {
                ec.clear();
                co_return 0;
            }
            std::size_t done = 0;
            while (done < buffer.size())
            {
                const auto n = std::min(max_chunk_len, buffer.size() - done);
                std::vector<std::uint8_t> out(n + chunk_encryptor::overhead);
                const auto enc = enc_->seal(as_u8(buffer.subspan(done, n)), out);
                if (enc == 0)
                {
                    ec = make_error_code(error::bad_length);
                    co_return 0;
                }
                const auto wire = std::span<const std::uint8_t>(out.data(), enc);
                if (co_await send_bytes(wire))
                {
                    ec = make_error_code(error::io_error);
                    co_return 0;
                }
                done += n;
            }
            ec.clear();
            co_return buffer.size();
        }

        /**
         * @brief 关闭传输层
         * @details 透传关闭到底层传输，挂起的读写立即返回。
         */
        void close() override
        {
            if (next_layer_)
                next_layer_->close();
        }

        /**
         * @brief 取消未完成异步操作
         * @details 透传取消到底层传输，挂起的读立即返回 0。
         */
        void cancel() override
        {
            if (next_layer_)
                next_layer_->cancel();
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         * @return 内层传输指针
         */
        [[nodiscard]] auto next_layer() noexcept -> psmtest::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 内层传输指针
         */
        [[nodiscard]] auto next_layer() const noexcept -> const psmtest::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         * @return 底层传输共享指针（所有权转移给调用者）
         */
        [[nodiscard]] auto release() -> shared_transmission override
        {
            return std::move(next_layer_);
        }

        /**
         * @brief 执行客户端握手
         * @param target 目标地址
         * @param cmd 命令（默认 tcp；UDP 数据面传 command::udp）
         * @return 错误码
         * @details 生成随机参数 → 密封请求头（命令写入指令头）→
         * 发送 → 读取响应校验。
         * @warning 调用前必须确保 next_layer_ 已建立连接
         */
        [[nodiscard]] auto write_handshake(shared_transmission upstream, const address &target,
                                      command cmd = command::tcp) -> net::awaitable<error>
        {
            next_layer_ = std::move(upstream);
            // 1. 生成随机参数
            std::random_device rd;
            std::array<std::uint8_t, 16> iv{};
            std::array<std::uint8_t, 16> key{};
            for (auto &b : iv)
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            for (auto &b : key)
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            const auto v = static_cast<std::uint8_t>(rd() & 0xFF);
            const auto p = static_cast<std::uint8_t>(rd() % 16);
            std::array<std::uint8_t, 4> random4{};
            for (auto &b : random4)
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            const auto time_sec =
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count();

            // 2. 构造请求头明文并密封
            request_header hdr;
            hdr.version = protocol_version;
            hdr.cmd = cmd;
            hdr.opt = 0x01; // chunk_stream 分块传输
            hdr.sec = security::aes_128_gcm;
            hdr.target = target;
            const auto plain = build_request_header(hdr, iv, key, v, p);
            const auto cmd_key = cmd_key_from_uuid(uuid_);
            const auto sealed = seal_auth_header(cmd_key, plain, time_sec, random4);
            const auto auth_id = create_auth_id(time_sec, random4);
            if (co_await send_bytes(sealed))
                co_return error::io_error;

            // 3. 读取 18 字节响应长度块
            std::array<std::uint8_t, 18> len_enc{};
            if (co_await recv_exact(std::span<std::uint8_t>(len_enc)))
                co_return error::io_error;

            // 4. 派生响应密钥并解密长度字段
            const auto resp_body_key = detail::sha256(key);
            const auto resp_body_iv = detail::sha256(iv);
            std::array<std::uint8_t, 16> resp_key16{};
            std::memcpy(resp_key16.data(), resp_body_key.data(), 16);
            std::array<std::uint8_t, 16> resp_iv16{};
            std::memcpy(resp_iv16.data(), resp_body_iv.data(), 16);
            const auto resp_len_key = kdf(resp_key16, kdf_resp_len_key);
            const auto resp_len_iv = kdf(resp_iv16, kdf_resp_len_iv);
            std::array<std::uint8_t, 16> rlk{};
            std::memcpy(rlk.data(), resp_len_key.data(), 16);
            std::array<std::uint8_t, 12> rliv{};
            std::memcpy(rliv.data(), resp_len_iv.data(), 12);
            const auto len_plain = detail::aes_gcm_open(rlk, rliv, len_enc, auth_id);
            if (len_plain.size() != 2)
                co_return error::bad_auth;
            const auto resp_len = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];

            // 5. 读取响应头密文并校验验证字节
            std::vector<std::uint8_t> resp_enc(resp_len);
            if (co_await recv_exact(resp_enc))
                co_return error::io_error;
            const auto resp_key = kdf(resp_key16, kdf_resp_key);
            const auto resp_iv = kdf(resp_iv16, kdf_resp_iv);
            std::array<std::uint8_t, 16> rk{};
            std::memcpy(rk.data(), resp_key.data(), 16);
            std::array<std::uint8_t, 12> riv{};
            std::memcpy(riv.data(), resp_iv.data(), 12);
            response_header rh;
            if (open_response_header(rk, riv, resp_enc, auth_id, rh) != error::none)
                co_return error::bad_auth;
            if (rh.version != v)
                co_return error::bad_auth;

            // 6. 派生分块密钥（body_key = KDF(request_key, request_nonce)）
            const auto body_key = kdf(key, iv);
            std::array<std::uint8_t, 16> chunk_key{};
            std::memcpy(chunk_key.data(), body_key.data(), 16);
            std::array<std::uint8_t, 12> chunk_nonce{};
            std::memcpy(chunk_nonce.data(), iv.data(), 12);
            enc_.emplace(chunk_key, chunk_nonce);
            dec_.emplace(chunk_key, chunk_nonce);
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 发送一个 UDP 数据报（UDP 数据面，chunk 即包边界）
         * @param payload 数据报载荷
         * @return 错误码
         * @details 目标地址固定来自指令头（不随包携带）。一次调用 =
         * 加密并发送一个数据分块（长度密文 + 载荷密文），对端
         * async_receive_datagram 恰好读到该分块即完整数据报。
         * @warning 仅在 handshake() 使用 command::udp 后调用；数据报
         * 模式与流式模式互斥，同一会话不可混用
         */
        [[nodiscard]] auto async_send_datagram(std::span<const std::uint8_t> payload)
            -> net::awaitable<error>
        {
            if (!handshaken_)
                co_return error::not_open;
            std::vector<std::uint8_t> out(payload.size() + chunk_encryptor::overhead);
            const auto n = enc_->seal(payload, out);
            if (n == 0)
                co_return error::bad_length;
            const auto wire = std::span<const std::uint8_t>(out.data(), n);
            co_return co_await send_bytes(wire) ? error::io_error : error::none;
        }

        /**
         * @brief 接收一个 UDP 数据报（UDP 数据面，chunk 即包边界）
         * @param payload 输出数据报载荷
         * @return 错误码
         * @details 一次调用 = 读取并解密一个数据分块，分块明文即完整
         * 数据报。读到结束块（len=0）返回 unexpected_eof。
         * @warning 仅在 handshake() 使用 command::udp 后调用；数据报
         * 模式与流式模式互斥，同一会话不可混用
         */
        [[nodiscard]] auto async_receive_datagram(std::vector<std::uint8_t> &payload)
            -> net::awaitable<error>
        {
            if (!handshaken_)
                co_return error::not_open;
            if (eof_)
                co_return error::unexpected_eof;
            const auto err = co_await read_chunk();
            if (err != error::none)
                co_return err;
            if (eof_)
                co_return error::unexpected_eof;
            payload = std::move(plain_rx_);
            plain_off_ = 0;
            co_return error::none;
        }

        /**
         * @brief 服务端握手：解析认证头 → 校验 → 发送 AEAD 响应
         * @param upstream 上游传输（所有权移交）
         * @return 错误码与解析的请求
         * @details 精确分段读取认证头（42B 前缀 → 解密长度 → 请求头
         * 密文），cmdKey 解密成功即 UUID 匹配，发送 38B 响应头并
         * 派生分块密钥。认证失败不发送响应，静默断开。
         */
        [[nodiscard]] auto read_handshake(shared_transmission upstream)
            -> net::awaitable<std::pair<error, message>>
        {
            next_layer_ = std::move(upstream);
            message out;
            auto err = co_await read_request(out);
            if (err != error::none)
                co_return std::pair{err, message{}};

            // 命令校验（tcp/udp/mux 合法）
            const auto cmd = static_cast<command>(out.cmd);
            if (cmd != command::tcp && cmd != command::udp && cmd != command::mux)
                co_return std::pair{error::bad_message, message{}};

            // 发送 AEAD 响应头
            err = co_await send_success(out);
            if (err != error::none)
                co_return std::pair{err, message{}};

            // 派生分块密钥（body_key = KDF(request_key, request_nonce) 前 16 字节）
            const auto body_key = kdf(out.request_key, out.request_nonce);
            std::array<std::uint8_t, 16> chunk_key{};
            std::memcpy(chunk_key.data(), body_key.data(), 16);
            std::array<std::uint8_t, 12> chunk_nonce{};
            std::memcpy(chunk_nonce.data(), out.request_nonce.data(), 12);
            enc_.emplace(chunk_key, chunk_nonce);
            dec_.emplace(chunk_key, chunk_nonce);
            handshaken_ = true;
            parsed_ = out;
            co_return std::pair{error::none, std::move(out)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（read_handshake 成功后有效）
         */
        [[nodiscard]] auto parsed() const -> const message &
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
        [[nodiscard]] auto read_request(message &out) -> net::awaitable<error>
        {
            // 1. 读取认证头前缀（16 AuthID + 18 LenEnc + 8 Nonce = 42 字节）
            std::array<std::uint8_t, 42> prefix{};
            if (co_await recv_exact(std::span<std::uint8_t>(prefix)))
                co_return error::io_error;

            // 2. 解密长度字段，确定请求头密文总长
            const auto cmd_key = cmd_key_from_uuid(uuid_);
            const auto auth_id = std::span<const std::uint8_t>(prefix).first(16);
            std::memcpy(auth_id_.data(), auth_id.data(), 16); // 响应 AAD 复用
            const auto nonce8 = std::span<const std::uint8_t>(prefix).subspan(34, 8);
            const auto len_key = kdf(cmd_key, kdf_header_len_key, auth_id, nonce8);
            const auto len_iv = kdf(cmd_key, kdf_header_len_iv, auth_id, nonce8);
            std::array<std::uint8_t, 16> lk{};
            std::memcpy(lk.data(), len_key.data(), 16);
            std::array<std::uint8_t, 12> liv{};
            std::memcpy(liv.data(), len_iv.data(), 12);
            const auto len_plain = detail::aes_gcm_open(
                lk, liv, std::span<const std::uint8_t>(prefix).subspan(16, 18), auth_id);
            if (len_plain.size() != 2)
                co_return error::bad_auth;
            const auto length = static_cast<std::size_t>(len_plain[0]) << 8 | len_plain[1];

            // 3. 读取请求头密文（length + 16 tag）
            std::vector<std::uint8_t> body_enc(length + 16);
            if (co_await recv_exact(body_enc))
                co_return error::io_error;

            // 4. 组装完整认证头，复用 handshake 的 parser 解析
            std::vector<std::uint8_t> full;
            full.reserve(prefix.size() + body_enc.size());
            full.insert(full.end(), prefix.begin(), prefix.end());
            full.insert(full.end(), body_enc.begin(), body_enc.end());
            parser p(uuid_);
            std::error_code pec;
            p.put(boost::asio::const_buffer(full.data(), full.size()), pec);
            if (pec || !p.is_done())
                co_return error::bad_auth;

            // 5. UUID 校验（AEAD 解密成功即隐含 cmdKey 匹配，此处显式确认）
            out = p.get();
            if (out.uuid != uuid_)
                co_return error::bad_auth;
            co_return error::none;
        }

        /**
         * @brief 发送 AEAD 响应头（38B）
         * @param req 请求消息（request_key / request_nonce / resp_header）
         * @return 错误码
         * @details AAD = 请求的 AuthID（对齐 mihomo：客户端以自身
         * AuthID 校验响应）。
         */
        [[nodiscard]] auto send_success(const message &req) const -> net::awaitable<error>
        {
            const auto resp_body_key = detail::sha256(req.request_key);
            const auto resp_body_iv = detail::sha256(req.request_nonce);
            std::array<std::uint8_t, 16> resp_key16{};
            std::memcpy(resp_key16.data(), resp_body_key.data(), 16);
            std::array<std::uint8_t, 16> resp_iv16{};
            std::memcpy(resp_iv16.data(), resp_body_iv.data(), 16);

            const std::array<std::uint8_t, 4> v_plain{req.resp_header, 0, 0, 0};
            const auto resp_key = kdf(resp_key16, kdf_resp_key);
            const auto resp_iv = kdf(resp_iv16, kdf_resp_iv);
            std::array<std::uint8_t, 16> rk{};
            std::memcpy(rk.data(), resp_key.data(), 16);
            std::array<std::uint8_t, 12> riv{};
            std::memcpy(riv.data(), resp_iv.data(), 12);
            const auto resp_enc = seal_response_header(rk, riv, v_plain, auth_id_);

            const auto resp_len_key = kdf(resp_key16, kdf_resp_len_key);
            const auto resp_len_iv = kdf(resp_iv16, kdf_resp_len_iv);
            std::array<std::uint8_t, 16> rlk{};
            std::memcpy(rlk.data(), resp_len_key.data(), 16);
            std::array<std::uint8_t, 12> rliv{};
            std::memcpy(rliv.data(), resp_len_iv.data(), 12);
            const std::array<std::uint8_t, 2> resp_len_plain{
                static_cast<std::uint8_t>(resp_enc.size() >> 8),
                static_cast<std::uint8_t>(resp_enc.size() & 0xFF)};
            const auto len_enc = detail::aes_gcm_seal(rlk, rliv, resp_len_plain, auth_id_);

            std::vector<std::uint8_t> resp;
            resp.reserve(len_enc.size() + resp_enc.size());
            resp.insert(resp.end(), len_enc.begin(), len_enc.end());
            resp.insert(resp.end(), resp_enc.begin(), resp_enc.end());
            co_return co_await send_bytes(resp) ? error::io_error : error::none;
        }

        /**
         * @brief 读取并解密一个数据分块（内部循环补读）
         * @return 错误码；none 且 eof_ = 结束块
         * @details 块格式：[2B 长度密文 + 16B tag][载荷密文 + 16B tag]。
         * 解密失败（tag 校验）返回 bad_auth。
         */
        [[nodiscard]] auto read_chunk() -> net::awaitable<error>
        {
            // 1. 读取 18 字节块头（长度密文 + 16 tag）
            std::array<std::uint8_t, 18> head{};
            if (co_await recv_exact(std::span<std::uint8_t>(head)))
                co_return error::unexpected_eof;

            // 2. 解密长度字段
            auto len = dec_->open_len(head);
            if (!len)
                co_return len.error();
            if (*len == 0) // 结束块
            {
                eof_ = true;
                co_return error::none;
            }

            // 3. 读取载荷密文（len + 16 tag）并解密
            std::vector<std::uint8_t> enc(*len + 16);
            if (co_await recv_exact(enc))
                co_return error::unexpected_eof;
            std::vector<std::uint8_t> plain(*len);
            const auto err = dec_->open_payload(enc, plain);
            if (err != error::none)
                co_return err;

            // 4. 存入待读缓冲
            plain_rx_ = std::move(plain);
            plain_off_ = 0;
            co_return error::none;
        }

        /**
         * @brief 精确读取指定字节数（内部循环补读）
         * @param buf 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto recv_exact(std::span<std::uint8_t> buf) -> net::awaitable<bool>
        {
            std::size_t done = 0;
            while (done < buf.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(as_bytes(buf.subspan(done)), ec);
                if (ec || n == 0)
                    co_return true;
                done += n;
            }
            co_return false;
        }

        /**
         * @brief 发送全部字节
         * @param data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto send_bytes(std::span<const std::uint8_t> data) const
            -> net::awaitable<bool>
        {
            std::size_t done = 0;
            while (done < data.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_write_some(as_bytes(data.subspan(done)), ec);
                if (ec)
                    co_return true;
                done += n;
            }
            co_return false;
        }

        shared_transmission next_layer_;          ///< 底层传输（独占所有权）
        std::array<std::uint8_t, 16> auth_id_{};  ///< 请求 AuthID（响应 AAD）
        message parsed_{};                        ///< 服务端握手解析结果
        std::array<std::uint8_t, 16> uuid_;        ///< 协议 UUID（凭据）
        std::optional<chunk_encryptor> enc_;      ///< 分块加密器（发送侧）
        std::optional<chunk_decryptor> dec_;      ///< 分块解密器（接收侧）
        std::vector<std::uint8_t> plain_rx_;      ///< 解密后明文缓冲
        std::size_t plain_off_{0};                ///< 明文缓冲消费偏移
        bool handshaken_{false};                  ///< 握手完成标志
        bool eof_{false};                         ///< 已读到结束块 / 对端关闭
    };

    /// 流连接共享指针
    using shared_conn = std::shared_ptr<conn>;

    static_assert(psmtest::transmission_like<conn>);

} // namespace psmtest::vmess
