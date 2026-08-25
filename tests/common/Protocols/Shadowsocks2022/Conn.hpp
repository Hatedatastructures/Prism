/**
 * @file Conn.hpp
 * @brief Shadowsocks 2022 客户端会话（Transmission 装饰器）
 * @details 客户端视角的完整 SS2022（SIP022 AEAD）实现：
 * 1. 生成随机 salt（16 字节）→ 派生会话密钥（BLAKE3）
 * 2. 构造固定头 + 变长头（地址 + padding + 初始载荷）加密
 * 3. 发送 [salt][固定头密文][变长头密文]
 * 4. 读取响应固定头并校验类型字节（0x01）
 * 5. 隧道：AsyncReadSome 解密 chunk（上限 0x3FFF），
 *    AsyncWriteSome 分块加密发送；发送侧 Nonce 与握手衔接
 * 6. UDP 数据面：AsyncSendDatagram / AsyncReceiveDatagram
 *    逐包 AEAD 编解码（Codec.hpp 纯函数），目标地址随包携带；
 *    数据报平面与隧道流平面互斥（同一会话二选一）
 * @note 与 Server.hpp 配对使用（服务端/客户端分离设计）
 * @note 实例非线程安全，应在同一协程或线程内使用
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <openssl/rand.h>

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

#include <common/Core/ByteSpan.hpp>
#include <common/Core/Error.hpp>
#include <common/Core/Memory/Pointer.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Shadowsocks2022/Codec.hpp>
#include <common/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    namespace ss = Preview::Shadowsocks2022;

    /**
     * @class Client
     * @brief SS2022 客户端会话
     * @details 将底层传输层包装为 SS2022 客户端，持有底层传输的
     * 独占所有权。handshake(Target) 完成首包发送与响应校验，成功后
     * 通过 Transmission 接口透传（加解密）隧道数据，或通过
     * AsyncSendDatagram / AsyncReceiveDatagram 收发 UDP 数据报。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /// 底层预读批量大小（多 chunk 共享一次 IOCP 往返）

        /**
         * @brief 构造函数
         * @param NextLayer 已建立连接的底层传输
         * @param cfg 客户端配置
         * @details 接管底层传输所有权，调用者不应再使用原指针。
         */
        explicit Conn(std::string password) : psk_(DerivePsk(password))
        {
        }

        /**
         * @brief 构造函数（直接指定 16 字节 PSK）
         * @param psk 标准配置 PSK（base64 psk 解码后的原始字节）
         * @details 与生产 Prism / sing-shadowsocks 配置一致：
         * 标准 SS2022 PSK 是 base64 解码后的原始字节，不走密码派生。
         */
        explicit Conn(std::array<std::uint8_t, 16> psk) : psk_(psk)
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
         * @warning 未握手或已结束时返回 0 并置 ec；与数据报模式互斥
         */
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
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
         * @brief 异步写入（加密后发送，0x3FFF 分块）
         * @param Buffer 发送缓冲区（明文）
         * @param ec 错误码输出参数
         * @return 实际写入的明文长度
         * @details SS2022 chunk 上限 0x3FFF：超过时按块分片加密发送。
         * @warning 未握手时返回 0 并置 ec；与数据报模式互斥
         */
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
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
            auto out = mem_.template MakeBuffer<std::uint8_t>(ss::MaxChunkSize + 2 * ss::AeadTagLen + 2);
            while (Done < Buffer.size())
            {
                const auto n = std::min(static_cast<std::size_t>(ss::MaxChunkSize), Buffer.size() - Done);
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
         * @return 错误码
         * @details 构造并发送首包，读取响应固定头校验类型字节，
         * 保存会话密钥（UDP 数据面复用）。
         * @warning 调用前必须确保 next_layer_ 已建立连接
         */
        [[nodiscard]] auto WriteHandshake(SharedTransmission upstream, const ss::Address &Target)
            -> net::awaitable<Error>
        {
            next_layer_ = std::move(upstream);
            // 1. 生成随机盐并派生会话密钥
            // @note 盐必须 CSPRNG：MinGW 的 std::random_device 存在确定性序列风险，
            //       盐重复 = 跨会话 keystream 重用（与生产 RAND_bytes 口径一致）
            std::array<std::uint8_t, 16> salt{};
            RAND_bytes(salt.data(), static_cast<int>(salt.size()));
            const auto key = ss::SessionKey(psk_, salt, 16);

            // 2. 构造固定头 + 变长头（地址 + padding + 初始载荷）
            std::random_device rd; // padding 长度非密码学用途，random_device 足够
            const auto TimeSec =
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count());
            const auto PadLen = static_cast<std::uint16_t>(1 + rd() % 16);
            const auto VarPlain = ss::BuildVarHeader(Target, PadLen, {});
            const auto FixedPlain = ss::ParseFixedHeader(ss::HeaderTypeClient, TimeSec,
                                                            static_cast<std::uint16_t>(VarPlain.size()));

            // 3. 加密并发送 [salt][固定头密文][变长头密文]
            ss::ChunkCodec Codec(key);
            const auto FixedEnc = Codec.SealRaw(FixedPlain);
            const auto VarEnc = Codec.SealRaw(VarPlain);
            std::vector<std::uint8_t> wire;
            wire.reserve(salt.size() + FixedEnc.size() + VarEnc.size());
            wire.insert(wire.end(), salt.begin(), salt.end());
            wire.insert(wire.end(), FixedEnc.begin(), FixedEnc.end());
            wire.insert(wire.end(), VarEnc.begin(), VarEnc.end());
            if (co_await SendBytes(wire))
            {
                co_return Error::io_error;
            }

            // 4. 读取标准响应：Server salt(16) + 裸块固定头（27B 明文 + 16B tag）
            std::array<std::uint8_t, 16> server_salt{};
            if (co_await RecvExact(std::span<std::uint8_t>(server_salt)))
            {
                co_return Error::io_error;
            }
            const auto RespKey = ss::SessionKey(psk_, server_salt, 16);
            ss::ChunkCodec resp_codec(RespKey);
            std::array<std::uint8_t, ss::RespFixedHdrSize> RespEnc{};
            if (co_await RecvExact(std::span<std::uint8_t>(RespEnc)))
            {
                co_return Error::io_error;
            }
            const auto RespPlain = resp_codec.OpenRaw(RespEnc);
            if (RespPlain.size() != ss::RespFixedHdrPlain ||
                RespPlain[0] != ss::HeaderTypeServer)
            {
                co_return Error::bad_auth;
            }
            // 校验 requestSalt 回显
            if (std::memcmp(RespPlain.data() + 9, salt.data(), 16) != 0)
            {
                co_return Error::bad_auth;
            }
            // 响应初始载荷（若有）：裸块，缓存为数据面首个读块
            const auto RespPayloadLen =
                static_cast<std::size_t>(RespPlain[25]) << 8 | RespPlain[26];
            if (RespPayloadLen > 0)
            {
                typename std::template Buffer<std::uint8_t> PayloadEnc =
                    mem_.template MakeBuffer<std::uint8_t>(RespPayloadLen + ss::AeadTagLen);
                if (co_await RecvExact(PayloadEnc))
                {
                    co_return Error::io_error;
                }
                auto payload = resp_codec.OpenRaw(PayloadEnc);
                if (payload.empty())
                {
                    co_return Error::bad_auth;
                }
                PlainRx_.assign(payload.begin(), payload.end());
                PlainOff_ = 0;
            }
            else
            {
                // 标准响应固定头后总是跟一个 AEAD 块（SIP022 读响应流程）：
                // payloadLen=0 时为 16B 空块（Seal(0B)），必须消费以保持数据面 chunk 对齐
                std::array<std::uint8_t, ss::AeadTagLen> empty_block{};
                if (co_await RecvExact(std::span<std::uint8_t>(empty_block)))
                {
                    co_return Error::io_error;
                }
                std::vector<std::uint8_t> EmptyPlain;
                if (!resp_codec.OpenRaw(empty_block, EmptyPlain))
                {
                    co_return Error::bad_auth;
                }
            }

            // 5. 初始化编解码器：发送侧 Nonce 已推进到数据块起始，
            //    接收侧响应已消耗 Nonce 0-1
            enc_.emplace(std::move(Codec));
            dec_.emplace(std::move(resp_codec));
            std::memcpy(session_key_.data(), key.data(), 16);
            handshaken_ = true;
            co_return Error::none;
        }

        /**
         * @brief 发送一个 UDP 数据报（UDP 数据面）
         * @param Target 目标地址（明文写入数据报头部）
         * @param payload 数据报载荷
         * @return 错误码
         * @details 逐包 AEAD 加密（BuildUdpPacket），packet_id 每次
         * 自增（兼作 Nonce 与防重放依据）。数据报直接写入底层流，
         * 不经过隧道 chunk 状态机。
         * @warning 仅在握手成功后调用；数据报模式与流式模式互斥，
         * 同一会话不可混用
         */
        [[nodiscard]] auto AsyncSendDatagram(const ss::Address &Target,
                                               std::span<const std::uint8_t> payload) -> net::awaitable<Error>
        {
            if (!handshaken_)
            {
                co_return Error::not_open;
            }
            const auto packet =
                ss::BuildUdpPacket(ss::UdpBuildInput{session_key_, ++UdpPktId_, &Target, payload});
            if (packet.empty())
            {
                co_return Error::bad_length;
            }
            if (co_await SendBytes(packet))
            {
                co_return Error::io_error;
            }
            co_return Error::none;
        }

        /**
         * @brief 接收一个 UDP 数据报（UDP 数据面）
         * @param Target 输出目标地址
         * @param payload 输出数据报载荷
         * @return 错误码
         * @details 明文头部（SeparateHeader + Type + TS + 地址）精确
         * 分段读取，剩余密文单次读取（发送方须单次写入完整数据报，
         * MemoryStream 单次 WriteAll 即一个数据报边界），最后
         * ParseUdpPacket 校验并解密。
         * @warning 仅在握手成功后调用；数据报模式与流式模式互斥，
         * 同一会话不可混用
         */
        [[nodiscard]] auto AsyncReceiveDatagram(ss::Address &Target, std::vector<std::uint8_t> &payload)
            -> net::awaitable<Error>
        {
            if (!handshaken_)
            {
                co_return Error::not_open;
            }

            // 1. SeparateHeader（16B 明文）：SessionID + PacketID
            std::array<std::uint8_t, ss::SeparateHdrLen> separate{};
            if (co_await UdpReadExact(std::span<std::uint8_t>(separate)))
            {
                co_return Error::unexpected_eof;
            }

            // 2. 明文 Type + Timestamp
            std::array<std::uint8_t, 1 + ss::UdpTsLen> head{};
            if (co_await UdpReadExact(std::span<std::uint8_t>(head)))
            {
                co_return Error::unexpected_eof;
            }
            if (head[0] != ss::UdpType)
            {
                co_return Error::bad_message;
            }

            // 3. ATYP + 地址体 + PORT（明文，可精确分段）
            std::array<std::uint8_t, 1> atyp{};
            if (co_await UdpReadExact(std::span<std::uint8_t>(atyp)))
            {
                co_return Error::unexpected_eof;
            }
            const auto AtypType = static_cast<ss::AddressType>(atyp[0]);
            std::size_t AddrLen = 0;
            std::uint8_t DomainLen = 0;
            if (AtypType == ss::AddressType::Ipv4)
            {
                AddrLen = 4;
            }
            else if (AtypType == ss::AddressType::Ipv6)
            {
                AddrLen = 16;
            }
            else if (AtypType == ss::AddressType::Domain)
            {
                std::array<std::uint8_t, 1> dlen{};
                if (co_await UdpReadExact(std::span<std::uint8_t>(dlen)))
                {
                    co_return Error::unexpected_eof;
                }
                DomainLen = dlen[0];
                AddrLen = dlen[0];
            }
            else
            {
                co_return Error::bad_message;
            }
            std::vector<std::uint8_t> addr_body(AddrLen);
            if (co_await UdpReadExact(addr_body))
            {
                co_return Error::unexpected_eof;
            }
            std::array<std::uint8_t, 2> port{};
            if (co_await UdpReadExact(std::span<std::uint8_t>(port)))
            {
                co_return Error::unexpected_eof;
            }

            // 4. 剩余密文 + tag：从预读缓冲取（不足再读底层）
            UdpRx_.clear();
            if (UdpUsed_ > 0)
            {
                UdpRx_.assign(UdpBuf_.begin(), UdpBuf_.begin() + static_cast<std::ptrdiff_t>(UdpUsed_));
                UdpBuf_.clear();
                UdpUsed_ = 0;
            }
            else
            {
                std::array<std::uint8_t, 512> chunk{};
                std::error_code ec;
                const auto n =
                    co_await next_layer_->AsyncReadSome(AsBytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec || n == 0)
                {
                    co_return Error::unexpected_eof;
                }
                UdpRx_.assign(chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
            }
            const auto n = UdpRx_.size();

            // 5. 组装完整数据报并解析（解密 + 校验）
            std::vector<std::uint8_t> packet;
            packet.reserve(ss::SeparateHdrLen + head.size() + 1 + addr_body.size() + 2 + n);
            packet.insert(packet.end(), separate.begin(), separate.end());
            packet.insert(packet.end(), head.begin(), head.end());
            packet.insert(packet.end(), atyp.begin(), atyp.end());
            if (DomainLen > 0)
            {
                packet.push_back(DomainLen);
            }
            packet.insert(packet.end(), addr_body.begin(), addr_body.end());
            packet.insert(packet.end(), port.begin(), port.end());
            packet.insert(packet.end(), UdpRx_.begin(), UdpRx_.begin() + static_cast<std::ptrdiff_t>(n));
            co_return ss::ParseUdpPacket(ss::UdpParseInput{session_key_, packet, &Target, &payload});
        }

        /**
         * @brief 服务端握手：解析首包 → 发送响应
         * @param upstream 上游传输（所有权移交）
         * @return 错误码与解析的请求
         * @details 精确分段读取首包（salt → 固定头解密 + 时间窗校验
         * → 变长头地址解析），发送响应固定头并初始化发送侧编解码器。
         */
        [[nodiscard]] auto ReadHandshake(SharedTransmission upstream)
            -> net::awaitable<std::pair<Error, ss::Message>>
        {
            next_layer_ = std::move(upstream);
            ss::Message Parsed;
            auto err = co_await ReadRequest(Parsed);
            if (err != Error::none)
            {
                co_return std::pair{err, ss::Message{}};
            }

            err = co_await SendSuccess();
            if (err != Error::none)
            {
                co_return std::pair{err, ss::Message{}};
            }
            handshaken_ = true;
            parsed_ = Parsed;
            co_return std::pair{Error::none, std::move(Parsed)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（ReadHandshake 成功后有效）
         */
        [[nodiscard]] auto Parsed() const -> const ss::Message &
        {
            return parsed_;
        }

        /**
         * @brief 精确分段读取（供包连接复用预读缓冲）
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExact(std::span<std::uint8_t> dst) -> net::awaitable<bool>
        {
            return RecvExact(dst);
        }

    private:
        /**
         * @brief 密码派生 16 字节 PSK（测试库约定：SHA256 前 16 字节）
         * @param password 密码
         * @return PSK
         */
        [[nodiscard]] static auto DerivePsk(std::string_view password) -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 32> Hash{};
            unsigned int len = 0;
            EVP_Digest(password.data(), password.size(), Hash.data(), &len, EVP_sha256(), nullptr);
            std::array<std::uint8_t, 16> psk{};
            std::memcpy(psk.data(), Hash.data(), 16);
            return psk;
        }

        /**
         * @brief 读取并解密一个数据分块（内部循环补读）
         * @return 错误码；none 且 eof_ = 结束块
         * @details 块格式：[2B 长度密文 + 16B tag][载荷密文 + 16B tag]。
         * 解密失败（tag 校验）返回 bad_auth。
         */
        [[nodiscard]] auto ReadChunk() -> net::awaitable<Error>
        {
            // 1. 读取 18 字节长度块
            std::array<std::uint8_t, ss::LenBlockSize> head{};
            if (co_await RecvExact(std::span<std::uint8_t>(head)))
            {
                co_return Error::unexpected_eof;
            }

            // 2. 解密长度字段
            auto len = dec_->OpenLen(head);
            if (!len)
            {
                co_return Error::bad_auth;
            }
            if (*len == 0) // 结束块
            {
                eof_ = true;
                co_return Error::none;
            }

            // 3. 读取载荷密文（len + 16 tag）并解密
            typename std::template Buffer<std::uint8_t> enc =
                mem_.template MakeBuffer<std::uint8_t>(*len + ss::AeadTagLen);
            if (co_await RecvExact(enc))
            {
                co_return Error::unexpected_eof;
            }
            // 解密直接写入 PlainRx_（消除临时 vector + 拷贝）
            PlainRx_.resize(*len);
            if (dec_->OpenPayload(enc, PlainRx_) == 0)
            {
                co_return Error::bad_auth;
            }
            PlainOff_ = 0;
            co_return Error::none;
        }

        /**
         * @brief 发送成功响应（响应固定头，独立 Nonce 从 0 起）
         * @return 错误码
         * @details 响应编解码器同时作为发送侧数据编解码器（Nonce 衔接）。
         */
        [[nodiscard]] auto SendSuccess() -> net::awaitable<Error>
        {
            const auto TimeSec =
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count());
            // 标准响应：Server salt(16) + 裸块固定头（Type + ts + requestSalt + payloadLen=0）
            // @note 盐必须 CSPRNG：MinGW 的 std::random_device 存在确定性序列风险，
            //       盐重复 = 跨会话 keystream 重用（与生产 RAND_bytes 口径一致）
            std::array<std::uint8_t, 16> server_salt{};
            RAND_bytes(server_salt.data(), static_cast<int>(server_salt.size()));
            const auto RespKey = ss::SessionKey(this->psk_, server_salt, 16);
            std::array<std::uint8_t, ss::RespFixedHdrPlain> RespPlain{};
            RespPlain[0] = ss::HeaderTypeServer;
            for (std::size_t i = 0; i < 8; ++i)
            {
                RespPlain[1 + i] =
                    static_cast<std::uint8_t>((TimeSec >> (56 - static_cast<unsigned>(i) * 8)) & 0xFF);
            }
            std::memcpy(RespPlain.data() + 9, this->client_salt_.data(), 16);
            ss::ChunkCodec resp_codec(RespKey);
            const auto RespEnc = resp_codec.SealRaw(RespPlain);
            // 标准读响应流程要求固定头后总是跟一个 AEAD 块：payloadLen=0 时为空块（16B）
            // 与 Prism / mihomo / sing readResponse（ReadWithLength(0) 读 0+16B）一致
            const auto EmptyEnc = resp_codec.SealRaw({});
            std::vector<std::uint8_t> wire;
            wire.reserve(server_salt.size() + RespEnc.size() + EmptyEnc.size());
            wire.insert(wire.end(), server_salt.begin(), server_salt.end());
            wire.insert(wire.end(), RespEnc.begin(), RespEnc.end());
            wire.insert(wire.end(), EmptyEnc.begin(), EmptyEnc.end());
            if (co_await SendBytes(wire))
            {
                co_return Error::io_error;
            }
            enc_.emplace(std::move(resp_codec));
            co_return Error::none;
        }

        /**
         * @brief 读取并解析握手首包（服务端）
         * @param out 输出请求消息（dst + 初始载荷）
         * @return 错误码
         * @details 分阶段读取：salt → 会话密钥派生 → 固定头解密 +
         * 类型/时间窗校验 → 变长头解密 + 地址解析。接收侧编解码器
         * 保留（Nonce 与数据流衔接）。
         */
        [[nodiscard]] auto ReadRequest(ss::Message &out) -> net::awaitable<Error>
        {
            // 1. 读取 salt（16 字节）
            std::array<std::uint8_t, 16> salt{};
            if (co_await RecvExact(std::span<std::uint8_t>(salt)))
            {
                co_return Error::io_error;
            }

            // 2. 派生会话密钥
            std::memcpy(this->client_salt_.data(), salt.data(), 16);
            const auto key = ss::SessionKey(this->psk_, salt, 16);

            // 3. 读取并解密裸块固定头（27B：11B 明文 + 16B tag）
            std::array<std::uint8_t, ss::FixedHdrSize> FixedEnc{};
            if (co_await RecvExact(std::span<std::uint8_t>(FixedEnc)))
            {
                co_return Error::io_error;
            }
            ss::ChunkCodec Codec(key);
            const auto FixedPlain = Codec.OpenRaw(FixedEnc);
            if (FixedPlain.size() != ss::FixedHdrPlain)
            {
                co_return Error::bad_auth;
            }
            if (FixedPlain[0] != ss::HeaderTypeClient)
            {
                co_return Error::bad_auth;
            }

            // 4. 时间戳校验（容忍窗口）
            std::uint64_t ts = 0;
            for (std::size_t i = 0; i < 8; ++i)
            {
                ts = (ts << 8) | FixedPlain[1 + i];
            }
            const auto now =
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count());
            std::uint64_t diff;
            if (now > ts)
            {
                diff = now - ts;
            }
            else
            {
                diff = ts - now;
            }
            if (diff > 90)
            {
                co_return Error::bad_auth;
            }
            const auto VarLen = static_cast<std::size_t>(FixedPlain[9]) << 8 | FixedPlain[10];

            // 5. 读取并解密裸块变长头（VarLen + 16B tag）
            std::vector<std::uint8_t> VarEnc(VarLen + ss::AeadTagLen);
            if (co_await RecvExact(VarEnc))
            {
                co_return Error::io_error;
            }
            const auto VarPlain = Codec.OpenRaw(VarEnc);
            if (VarPlain.empty())
            {
                co_return Error::bad_auth;
            }
            std::span<const std::uint8_t> payload;
            if (ss::ParseVarHeader(VarPlain, out.dst, payload) != Error::none)
            {
                co_return Error::bad_address;
            }
            if (!payload.empty())
            {
                out.InitialPayload.assign(reinterpret_cast<const char *>(payload.data()), payload.size());
            }

            // 6. 保存会话密钥与接收侧编解码器（Nonce 已推进到数据块起始）
            std::memcpy(session_key_.data(), key.data(), 16);
            dec_.emplace(std::move(Codec));
            co_return Error::none;
        }

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
         * @brief 精确读取指定字节数（UDP 数据面专用，独立于隧道缓冲）
         * @param buf 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         * @details 与 RecvExact 等价，但数据来自 UDP 数据报的明文
         * 头部；读取逻辑与隧道 chunk 读取互不干扰。
         */
        [[nodiscard]] auto UdpReadExact(std::span<std::uint8_t> buf) -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < buf.size())
            {
                if (UdpUsed_ > 0)
                {
                    const auto n = std::min(buf.size() - Done, UdpUsed_);
                    std::memcpy(buf.data() + Done, UdpBuf_.data(), n);
                    if (n < UdpUsed_)
                    {
                        std::memmove(UdpBuf_.data(), UdpBuf_.data() + n, UdpUsed_ - n);
                        UdpUsed_ -= n;
                    }
                    else
                    {
                        UdpBuf_.clear();
                        UdpUsed_ = 0;
                    }
                    Done += n;
                    continue;
                }
                std::array<std::uint8_t, 512> chunk{};
                std::error_code ec;
                const auto n =
                    co_await next_layer_->AsyncReadSome(AsBytes(std::span<std::uint8_t>(chunk)), ec);
                if (ec || n == 0)
                {
                    co_return true;
                }
                UdpBuf_.insert(UdpBuf_.end(), chunk.begin(),
                                chunk.begin() + static_cast<std::ptrdiff_t>(n));
                UdpUsed_ += n;
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

        SharedTransmission next_layer_; ///< 底层传输（独占所有权）

        std::array<std::uint8_t, 16> psk_{};         ///< 预派生 PSK
        std::array<std::uint8_t, 16> session_key_{}; ///< 会话密钥（握手后）
        std::array<std::uint8_t, 16> client_salt_{}; ///< 服务端：客户端握手盐（响应 requestSalt 回显）
        ss::Message parsed_{};                       ///< 服务端握手解析结果
        std::optional<ss::ChunkCodec> enc_;         ///< 发送侧编解码器
        std::optional<ss::ChunkCodec> dec_;         ///< 接收侧编解码器
        Memory mem_;                                 ///< 会话内存策略（Arena，热路径零释放分配）
        typename std::template Buffer<std::uint8_t> PlainRx_{mem_.Arena()}; ///< 解密后明文缓冲
        std::size_t PlainOff_{0};                   ///< 明文缓冲消费偏移
        typename std::template Buffer<std::uint8_t> UdpRx_{mem_.Arena()};   ///< UDP 数据报暂存缓冲
        std::uint64_t UdpPktId_{0};                ///< UDP 数据报递增包序号
        typename std::template Buffer<std::uint8_t> UdpBuf_{mem_.Arena()};  ///< UDP 预读缓冲
        std::size_t UdpUsed_{0};                    ///< UDP 缓冲有效字节数
        bool handshaken_{false};                     ///< 握手完成标志
        bool eof_{false};                            ///< 已读到结束块 / 对端关闭
    };


    /// 流连接共享指针
    using SharedConn = std::shared_ptr<Conn<>>;

} // namespace Preview::Shadowsocks2022
