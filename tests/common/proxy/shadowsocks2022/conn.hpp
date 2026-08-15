/**
 * @file conn.hpp
 * @brief Shadowsocks 2022 客户端会话（transmission 装饰器）
 * @details 客户端视角的完整 SS2022（SIP022 AEAD）实现：
 * 1. 生成随机 salt（16 字节）→ 派生会话密钥（BLAKE3）
 * 2. 构造固定头 + 变长头（地址 + padding + 初始载荷）加密
 * 3. 发送 [salt][固定头密文][变长头密文]
 * 4. 读取响应固定头并校验类型字节（0x01）
 * 5. 隧道：async_read_some 解密 chunk（上限 0x3FFF），
 *    async_write_some 分块加密发送；发送侧 nonce 与握手衔接
 * 6. UDP 数据面：async_send_datagram / async_receive_datagram
 *    逐包 AEAD 编解码（codec.hpp 纯函数），目标地址随包携带；
 *    数据报平面与隧道流平面互斥（同一会话二选一）
 * @note 与 server.hpp 配对使用（服务端/客户端分离设计）
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
#include <string_view>
#include <utility>
#include <vector>

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/memory/pointer.hpp>
#include <common/core/transmission.hpp>
#include <common/proxy/shadowsocks2022/codec.hpp>
#include <common/proxy/shadowsocks2022/types.hpp>

namespace psmtest::shadowsocks2022
{

    namespace ss = psmtest::ss2022;

    /**
     * @class client
     * @brief SS2022 客户端会话
     * @details 将底层传输层包装为 SS2022 客户端，持有底层传输的
     * 独占所有权。handshake(target) 完成首包发送与响应校验，成功后
     * 通过 transmission 接口透传（加解密）隧道数据，或通过
     * async_send_datagram / async_receive_datagram 收发 UDP 数据报。
     */
    template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
    class conn : public psmtest::transmission, public std::enable_shared_from_this<conn<Memory>>
    {
    public:
        /// 底层预读批量大小（多 chunk 共享一次 IOCP 往返）

        /**
         * @brief 构造函数
         * @param next_layer 已建立连接的底层传输
         * @param cfg 客户端配置
         * @details 接管底层传输所有权，调用者不应再使用原指针。
         */
        explicit conn(std::string password) : psk_(derive_psk(password))
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
         * @warning 未握手或已结束时返回 0 并置 ec；与数据报模式互斥
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
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
         * @brief 异步写入（加密后发送，0x3FFF 分块）
         * @param buffer 发送缓冲区（明文）
         * @param ec 错误码输出参数
         * @return 实际写入的明文长度
         * @details SS2022 chunk 上限 0x3FFF：超过时按块分片加密发送。
         * @warning 未握手时返回 0 并置 ec；与数据报模式互斥
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
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
            // 循环外复用加密缓冲（消除每块堆分配）；16KB+ 走线程局部池（分级分配）
            auto out = mem_.template make_buffer<std::uint8_t>(ss::max_chunk_size + 2 * ss::aead_tag_len + 2);
            while (done < buffer.size())
            {
                const auto n = std::min(static_cast<std::size_t>(ss::max_chunk_size), buffer.size() - done);
                const auto enc = enc_->seal(as_u8(buffer.subspan(done, n)), out);
                if (enc == 0)
                {
                    ec = make_error_code(error::bad_length);
                    co_return 0;
                }
                if (co_await send_bytes(std::span<const std::uint8_t>(out.data(), enc)))
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
            {
                next_layer_->close();
            }
        }

        /**
         * @brief 取消未完成异步操作
         * @details 透传取消到底层传输，挂起的读立即返回 0。
         */
        void cancel() override
        {
            if (next_layer_)
            {
                next_layer_->cancel();
            }
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
         * @brief 会话是否有效（已握手且底层存在）
         * @return 有效返回 true
         */
        [[nodiscard]] auto is_valid() const noexcept -> bool
        {
            return next_layer_ != nullptr && handshaken_;
        }

        /**
         * @brief 获取底层传输引用（非拥有）
         * @return 底层传输
         */
        [[nodiscard]] auto underlying() noexcept -> shared_transmission
        {
            return next_layer_;
        }

        /**
         * @brief 获取会话级内存竞技场
         * @return 非拥有资源指针（供握手/解析的临时分配）
         * @note 分配的对象随 conn 存活，conn 析构时一次性回收
         */
        [[nodiscard]] auto arena() noexcept -> psmtest::memory::resource_pointer
        {
            return mem_.arena();
        }

        /**
         * @brief 执行客户端握手
         * @param target 目标地址
         * @return 错误码
         * @details 构造并发送首包，读取响应固定头校验类型字节，
         * 保存会话密钥（UDP 数据面复用）。
         * @warning 调用前必须确保 next_layer_ 已建立连接
         */
        [[nodiscard]] auto write_handshake(shared_transmission upstream, const ss::address &target)
            -> net::awaitable<error>
        {
            next_layer_ = std::move(upstream);
            // 1. 生成随机 salt 并派生会话密钥
            std::random_device rd;
            std::array<std::uint8_t, 16> salt{};
            for (auto &b : salt)
            {
                b = static_cast<std::uint8_t>(rd() & 0xFF);
            }
            const auto key = ss::session_key(psk_, salt, 16);

            // 2. 构造固定头 + 变长头（地址 + padding + 初始载荷）
            const auto time_sec =
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count());
            const auto pad_len = static_cast<std::uint16_t>(1 + rd() % 16);
            const auto var_plain = ss::build_var_header(target, pad_len, {});
            const auto fixed_plain = ss::build_fixed_header(ss::header_type_client, time_sec,
                                                            static_cast<std::uint16_t>(var_plain.size()));

            // 3. 加密并发送 [salt][固定头密文][变长头密文]
            ss::chunk_codec codec(key);
            const auto fixed_enc = codec.seal(fixed_plain);
            const auto var_enc = codec.seal(var_plain);
            std::vector<std::uint8_t> wire;
            wire.reserve(salt.size() + fixed_enc.size() + var_enc.size());
            wire.insert(wire.end(), salt.begin(), salt.end());
            wire.insert(wire.end(), fixed_enc.begin(), fixed_enc.end());
            wire.insert(wire.end(), var_enc.begin(), var_enc.end());
            if (co_await send_bytes(wire))
            {
                co_return error::io_error;
            }

            // 4. 读取响应固定头（18B 长度块 + 27B 固定头密文）并校验
            std::array<std::uint8_t, ss::len_block_size + ss::fixed_hdr_size> resp_enc{};
            if (co_await recv_exact(std::span<std::uint8_t>(resp_enc)))
            {
                co_return error::io_error;
            }
            ss::chunk_codec resp_codec(key);
            std::size_t consumed = 0;
            const auto resp_plain = resp_codec.open(resp_enc, consumed);
            if (resp_plain.size() != ss::fixed_hdr_plain)
            {
                co_return error::bad_auth;
            }
            if (resp_plain[0] != ss::header_type_server)
            {
                co_return error::bad_auth;
            }

            // 5. 初始化编解码器：发送侧 nonce 已推进到数据块起始，
            //    接收侧响应已消耗 nonce 0-1
            enc_.emplace(std::move(codec));
            dec_.emplace(std::move(resp_codec));
            std::memcpy(session_key_.data(), key.data(), 16);
            handshaken_ = true;
            co_return error::none;
        }

        /**
         * @brief 发送一个 UDP 数据报（UDP 数据面）
         * @param target 目标地址（明文写入数据报头部）
         * @param payload 数据报载荷
         * @return 错误码
         * @details 逐包 AEAD 加密（build_udp_packet），packet_id 每次
         * 自增（兼作 nonce 与防重放依据）。数据报直接写入底层流，
         * 不经过隧道 chunk 状态机。
         * @warning 仅在握手成功后调用；数据报模式与流式模式互斥，
         * 同一会话不可混用
         */
        [[nodiscard]] auto async_send_datagram(const ss::address &target,
                                               std::span<const std::uint8_t> payload) -> net::awaitable<error>
        {
            if (!handshaken_)
            {
                co_return error::not_open;
            }
            const auto packet =
                ss::build_udp_packet(ss::udp_build_input{session_key_, ++udp_pkt_id_, &target, payload});
            if (packet.empty())
            {
                co_return error::bad_length;
            }
            co_return co_await send_bytes(packet) ? error::io_error : error::none;
        }

        /**
         * @brief 接收一个 UDP 数据报（UDP 数据面）
         * @param target 输出目标地址
         * @param payload 输出数据报载荷
         * @return 错误码
         * @details 明文头部（SeparateHeader + Type + TS + 地址）精确
         * 分段读取，剩余密文单次读取（发送方须单次写入完整数据报，
         * memory_stream 单次 write_all 即一个数据报边界），最后
         * parse_udp_packet 校验并解密。
         * @warning 仅在握手成功后调用；数据报模式与流式模式互斥，
         * 同一会话不可混用
         */
        [[nodiscard]] auto async_receive_datagram(ss::address &target, std::vector<std::uint8_t> &payload)
            -> net::awaitable<error>
        {
            if (!handshaken_)
            {
                co_return error::not_open;
            }

            // 1. SeparateHeader（16B 明文）：SessionID + PacketID
            std::array<std::uint8_t, ss::separate_hdr_len> separate{};
            if (co_await udp_read_exact(std::span<std::uint8_t>(separate)))
            {
                co_return error::unexpected_eof;
            }

            // 2. 明文 Type + Timestamp
            std::array<std::uint8_t, 1 + ss::udp_ts_len> head{};
            if (co_await udp_read_exact(std::span<std::uint8_t>(head)))
            {
                co_return error::unexpected_eof;
            }
            if (head[0] != ss::udp_type)
            {
                co_return error::bad_message;
            }

            // 3. ATYP + 地址体 + PORT（明文，可精确分段）
            std::array<std::uint8_t, 1> atyp{};
            if (co_await udp_read_exact(std::span<std::uint8_t>(atyp)))
            {
                co_return error::unexpected_eof;
            }
            const auto atyp_type = static_cast<ss::address_type>(atyp[0]);
            std::size_t addr_len = 0;
            std::uint8_t domain_len = 0;
            if (atyp_type == ss::address_type::ipv4)
            {
                addr_len = 4;
            }
            else if (atyp_type == ss::address_type::ipv6)
            {
                addr_len = 16;
            }
            else if (atyp_type == ss::address_type::domain)
            {
                std::array<std::uint8_t, 1> dlen{};
                if (co_await udp_read_exact(std::span<std::uint8_t>(dlen)))
                {
                    co_return error::unexpected_eof;
                }
                domain_len = dlen[0];
                addr_len = dlen[0];
            }
            else
            {
                co_return error::bad_message;
            }
            std::vector<std::uint8_t> addr_body(addr_len);
            if (co_await udp_read_exact(addr_body))
            {
                co_return error::unexpected_eof;
            }
            std::array<std::uint8_t, 2> port{};
            if (co_await udp_read_exact(std::span<std::uint8_t>(port)))
            {
                co_return error::unexpected_eof;
            }

            // 4. 剩余密文 + tag：从预读缓冲取（不足再读底层）
            udp_rx_.clear();
            if (udp_used_ > 0)
            {
                udp_rx_.assign(udp_buf_.begin(), udp_buf_.begin() + static_cast<std::ptrdiff_t>(udp_used_));
                udp_buf_.clear();
                udp_used_ = 0;
            }
            else
            {
                std::array<std::uint8_t, 512> chunk{};
                std::error_code ec;
                const auto n =
                    co_await next_layer_->async_read_some(as_bytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec || n == 0)
                {
                    co_return error::unexpected_eof;
                }
                udp_rx_.assign(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
            }
            const auto n = udp_rx_.size();

            // 5. 组装完整数据报并解析（解密 + 校验）
            std::vector<std::uint8_t> packet;
            packet.reserve(ss::separate_hdr_len + head.size() + 1 + addr_body.size() + 2 + n);
            packet.insert(packet.end(), separate.begin(), separate.end());
            packet.insert(packet.end(), head.begin(), head.end());
            packet.insert(packet.end(), atyp.begin(), atyp.end());
            if (domain_len > 0)
            {
                packet.push_back(domain_len);
            }
            packet.insert(packet.end(), addr_body.begin(), addr_body.end());
            packet.insert(packet.end(), port.begin(), port.end());
            packet.insert(packet.end(), udp_rx_.begin(), udp_rx_.begin() + static_cast<std::ptrdiff_t>(n));
            co_return ss::parse_udp_packet(ss::udp_parse_input{session_key_, packet, &target, &payload});
        }

        /**
         * @brief 服务端握手：解析首包 → 发送响应
         * @param upstream 上游传输（所有权移交）
         * @return 错误码与解析的请求
         * @details 精确分段读取首包（salt → 固定头解密 + 时间窗校验
         * → 变长头地址解析），发送响应固定头并初始化发送侧编解码器。
         */
        [[nodiscard]] auto read_handshake(shared_transmission upstream)
            -> net::awaitable<std::pair<error, ss::message>>
        {
            next_layer_ = std::move(upstream);
            ss::message parsed;
            auto err = co_await read_request(parsed);
            if (err != error::none)
            {
                co_return std::pair{err, ss::message{}};
            }

            err = co_await send_success();
            if (err != error::none)
            {
                co_return std::pair{err, ss::message{}};
            }
            handshaken_ = true;
            parsed_ = parsed;
            co_return std::pair{error::none, std::move(parsed)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（read_handshake 成功后有效）
         */
        [[nodiscard]] auto parsed() const -> const ss::message &
        {
            return parsed_;
        }

        /**
         * @brief 精确分段读取（供包连接复用预读缓冲）
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto read_exact(std::span<std::uint8_t> dst) -> net::awaitable<bool>
        {
            return recv_exact(dst);
        }

    private:
        /**
         * @brief 密码派生 16 字节 PSK（测试库约定：SHA256 前 16 字节）
         * @param password 密码
         * @return PSK
         */
        [[nodiscard]] static auto derive_psk(std::string_view password) -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 32> hash{};
            unsigned int len = 0;
            EVP_Digest(password.data(), password.size(), hash.data(), &len, EVP_sha256(), nullptr);
            std::array<std::uint8_t, 16> psk{};
            std::memcpy(psk.data(), hash.data(), 16);
            return psk;
        }

        /**
         * @brief 读取并解密一个数据分块（内部循环补读）
         * @return 错误码；none 且 eof_ = 结束块
         * @details 块格式：[2B 长度密文 + 16B tag][载荷密文 + 16B tag]。
         * 解密失败（tag 校验）返回 bad_auth。
         */
        [[nodiscard]] auto read_chunk() -> net::awaitable<error>
        {
            // 1. 读取 18 字节长度块
            std::array<std::uint8_t, ss::len_block_size> head{};
            if (co_await recv_exact(std::span<std::uint8_t>(head)))
            {
                co_return error::unexpected_eof;
            }

            // 2. 解密长度字段
            auto len = dec_->open_len(head);
            if (!len)
            {
                co_return error::bad_auth;
            }
            if (*len == 0) // 结束块
            {
                eof_ = true;
                co_return error::none;
            }

            // 3. 读取载荷密文（len + 16 tag）并解密
            typename Memory::template buffer<std::uint8_t> enc =
                mem_.template make_buffer<std::uint8_t>(*len + ss::aead_tag_len);
            if (co_await recv_exact(enc))
            {
                co_return error::unexpected_eof;
            }
            // 解密直接写入 plain_rx_（消除临时 vector + 拷贝）
            plain_rx_.resize(*len);
            if (dec_->open_payload(enc, plain_rx_) == 0)
            {
                co_return error::bad_auth;
            }
            plain_off_ = 0;
            co_return error::none;
        }

        /**
         * @brief 发送成功响应（响应固定头，独立 nonce 从 0 起）
         * @return 错误码
         * @details 响应编解码器同时作为发送侧数据编解码器（nonce 衔接）。
         */
        [[nodiscard]] auto send_success() -> net::awaitable<error>
        {
            const auto time_sec =
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count());
            const auto resp_plain = ss::build_fixed_header(ss::header_type_server, time_sec, 0);
            ss::chunk_codec resp_codec(session_key_);
            const auto resp_enc = resp_codec.seal(resp_plain);
            if (co_await send_bytes(resp_enc))
            {
                co_return error::io_error;
            }
            enc_.emplace(std::move(resp_codec));
            co_return error::none;
        }

        /**
         * @brief 读取并解析握手首包（服务端）
         * @param out 输出请求消息（dst + 初始载荷）
         * @return 错误码
         * @details 分阶段读取：salt → 会话密钥派生 → 固定头解密 +
         * 类型/时间窗校验 → 变长头解密 + 地址解析。接收侧编解码器
         * 保留（nonce 与数据流衔接）。
         */
        [[nodiscard]] auto read_request(ss::message &out) -> net::awaitable<error>
        {
            // 1. 读取 salt（16 字节）
            std::array<std::uint8_t, 16> salt{};
            if (co_await recv_exact(std::span<std::uint8_t>(salt)))
            {
                co_return error::io_error;
            }

            // 2. 派生会话密钥
            const auto key = ss::session_key(psk_, salt, 16);

            // 3. 读取并解密固定头（18B 长度块 + 27B 固定头密文）
            std::array<std::uint8_t, ss::len_block_size + ss::fixed_hdr_size> fixed_enc{};
            if (co_await recv_exact(std::span<std::uint8_t>(fixed_enc)))
            {
                co_return error::io_error;
            }
            ss::chunk_codec codec(key);
            std::size_t consumed = 0;
            const auto fixed_plain = codec.open(fixed_enc, consumed);
            if (fixed_plain.size() != ss::fixed_hdr_plain)
            {
                co_return error::bad_auth;
            }
            if (fixed_plain[0] != ss::header_type_client)
            {
                co_return error::bad_auth;
            }

            // 4. 时间戳校验（容忍窗口）
            std::uint64_t ts = 0;
            for (std::size_t i = 0; i < 8; ++i)
            {
                ts = (ts << 8) | fixed_plain[1 + i];
            }
            const auto now =
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count());
            const auto diff = now > ts ? now - ts : ts - now;
            if (diff > 90)
            {
                co_return error::bad_auth;
            }
            const auto var_len = static_cast<std::size_t>(fixed_plain[9]) << 8 | fixed_plain[10];

            // 5. 读取并解密变长头（18B 长度块 + var_len + 16B tag）
            std::vector<std::uint8_t> var_enc(ss::len_block_size + var_len + ss::aead_tag_len);
            if (co_await recv_exact(var_enc))
            {
                co_return error::io_error;
            }
            const auto var_plain = codec.open(var_enc, consumed);
            if (var_plain.empty())
            {
                co_return error::bad_auth;
            }
            std::span<const std::uint8_t> payload;
            if (ss::parse_var_header(var_plain, out.dst, payload) != error::none)
            {
                co_return error::bad_address;
            }
            if (!payload.empty())
            {
                out.initial_payload.assign(reinterpret_cast<const char *>(payload.data()), payload.size());
            }

            // 6. 保存会话密钥与接收侧编解码器（nonce 已推进到数据块起始）
            std::memcpy(session_key_.data(), key.data(), 16);
            dec_.emplace(std::move(codec));
            co_return error::none;
        }

        [[nodiscard]] auto recv_exact(std::span<std::uint8_t> buf) -> net::awaitable<bool>
        {
            std::size_t done = 0;
            while (done < buf.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(as_bytes(buf.subspan(done)), ec);
                if (ec || n == 0)
                {
                    co_return true;
                }
                done += n;
            }
            co_return false;
        }

        /**
         * @brief 精确读取指定字节数（UDP 数据面专用，独立于隧道缓冲）
         * @param buf 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         * @details 与 recv_exact 等价，但数据来自 UDP 数据报的明文
         * 头部；读取逻辑与隧道 chunk 读取互不干扰。
         */
        [[nodiscard]] auto udp_read_exact(std::span<std::uint8_t> buf) -> net::awaitable<bool>
        {
            std::size_t done = 0;
            while (done < buf.size())
            {
                if (udp_used_ > 0)
                {
                    const auto n = std::min(buf.size() - done, udp_used_);
                    std::memcpy(buf.data() + done, udp_buf_.data(), n);
                    if (n < udp_used_)
                    {
                        std::memmove(udp_buf_.data(), udp_buf_.data() + n, udp_used_ - n);
                        udp_used_ -= n;
                    }
                    else
                    {
                        udp_buf_.clear();
                        udp_used_ = 0;
                    }
                    done += n;
                    continue;
                }
                std::array<std::uint8_t, 512> chunk{};
                std::error_code ec;
                const auto n =
                    co_await next_layer_->async_read_some(as_bytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec || n == 0)
                {
                    co_return true;
                }
                udp_buf_.insert(udp_buf_.end(), chunk.begin(),
                                chunk.begin() + static_cast<std::ptrdiff_t>(n));
                udp_used_ += n;
            }
            co_return false;
        }

        /**
         * @brief 发送全部字节
         * @param data 数据
         * @return true = 失败
         */
        [[nodiscard]] auto send_bytes(std::span<const std::uint8_t> data) const -> net::awaitable<bool>
        {
            std::size_t done = 0;
            while (done < data.size())
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_write_some(as_bytes(data.subspan(done)), ec);
                if (ec)
                {
                    co_return true;
                }
                done += n;
            }
            co_return false;
        }

        shared_transmission next_layer_; ///< 底层传输（独占所有权）

        std::array<std::uint8_t, 16> psk_{};         ///< 预派生 PSK
        std::array<std::uint8_t, 16> session_key_{}; ///< 会话密钥（握手后）
        ss::message parsed_{};                       ///< 服务端握手解析结果
        std::optional<ss::chunk_codec> enc_;         ///< 发送侧编解码器
        std::optional<ss::chunk_codec> dec_;         ///< 接收侧编解码器
        Memory mem_;                                 ///< 会话内存策略（arena，热路径零释放分配）
        typename Memory::template buffer<std::uint8_t> plain_rx_{mem_.arena()}; ///< 解密后明文缓冲
        std::size_t plain_off_{0};                   ///< 明文缓冲消费偏移
        typename Memory::template buffer<std::uint8_t> udp_rx_{mem_.arena()};   ///< UDP 数据报暂存缓冲
        std::uint64_t udp_pkt_id_{0};                ///< UDP 数据报递增包序号
        typename Memory::template buffer<std::uint8_t> udp_buf_{mem_.arena()};  ///< UDP 预读缓冲
        std::size_t udp_used_{0};                    ///< UDP 缓冲有效字节数
        bool handshaken_{false};                     ///< 握手完成标志
        bool eof_{false};                            ///< 已读到结束块 / 对端关闭
    };


    /// 流连接共享指针
    using shared_conn = std::shared_ptr<conn<>>;

} // namespace psmtest::shadowsocks2022
