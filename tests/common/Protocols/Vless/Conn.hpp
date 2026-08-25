/**
 * @file Conn.hpp
 * @brief VLESS 流连接对象（TCP，实现 Transmission）
 * @details 单条 VLESS 连接的完整协议状态：
 * - 客户端握手：WriteHandshake(Target, cmd)（发送请求头 →
 *   读取 2 字节响应校验 Version 回显）
 * - 服务端握手：ReadHandshake()（四段精确解析：固定前缀 →
 *   Addons → 尾部 → 地址体，校验 version/uuid/cmd/atyp，
 *   发送 2 字节响应）
 * 握手后为纯字节流透传（预读缓冲优先）。UDP 数据面由 Dgram.hpp
 * 提供（独立包连接类型，嵌入本连接）。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Core/Memory/Pointer.hpp>
#include <common/Core/Protocol/Address.hpp>
#include <common/Core/Transmission.hpp>
#include <common/Protocols/Vless/Codec.hpp>
#include <common/Protocols/Vless/Types.hpp>

namespace Preview::Vless
{

    /**
     * @class Conn
     * @brief VLESS 流连接对象
     * @details 单条连接的协议状态：双端握手、数据透传、预读缓冲。
     * 实现 Transmission 接口可挂载装饰器链。由工厂创建，
     * 调用方以 shared_ptr 持有。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param upstream 上游传输（所有权移交）
         * @param uuid 协议 UUID（16 字节，凭据/校验用）
         * @param Auth 认证器（非拥有；nullptr = 静态比对 uuid）
         */
        explicit Conn(SharedTransmission upstream, std::array<std::uint8_t, UuidLen> uuid,
                      const Preview::Authenticator *Auth = nullptr)
            : next_layer_(std::move(upstream)), uuid_(uuid), auth_(Auth)
        {
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return next_layer_->Executor();
        }

        /**
         * @brief 异步读取（预读缓冲优先）
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数
         */
        [[nodiscard]] auto AsyncReadSome(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            if (used_ > 0)
            {
                const auto n = std::min(Buffer.size(), used_);
                std::memcpy(Buffer.data(), buf_.data(), n);
                if (n < used_)
                {
                    std::memmove(buf_.data(), buf_.data() + n, used_ - n);
                }
                else
                {
                    buf_.clear();
                }
                used_ -= n;
                co_return n;
            }
            co_return co_await next_layer_->AsyncReadSome(Buffer, ec);
        }

        /**
         * @brief 异步写入（透传）
         */
        [[nodiscard]] auto AsyncWriteSome(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->AsyncWriteSome(Buffer, ec);
        }

        /**
         * @brief 关闭传输层
         */
        void Close() override
        {
            if (next_layer_)
            {
                next_layer_->Close();
            }
        }

        /**
         * @brief 取消挂起操作
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
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
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
         * @brief 客户端握手：发送请求头 + 读取 2 字节响应
         * @param Target 目标地址
         * @param cmd 命令（默认 Tcp；UDP 场景传 udp）
         * @return 错误码
         * @details 构造请求头（version/uuid/cmd/Target）发送，
         * 读取 2 字节响应校验 Version 回显（对齐 Xray）。
         */
        [[nodiscard]] auto WriteHandshake(const Address &Target, Command cmd = Command::Tcp)
            -> net::awaitable<Error>
        {
            RequestHeader hdr;
            hdr.Version = ProtocolVersion;
            hdr.Uuid = uuid_;
            hdr.Cmd = cmd;
            hdr.Target = Target;
            const auto wire = BuildRequest(hdr);
            if (co_await SendBytes(wire))
            {
                co_return Error::io_error;
            }

            std::array<std::uint8_t, 2> resp{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(resp)))
            {
                co_return Error::io_error;
            }
            if (resp[0] != ProtocolVersion)
            {
                co_return Error::bad_magic;
            }
            handshaken_ = true;
            co_return Error::none;
        }

        /**
         * @brief 服务端握手：四段解析请求头 + 校验 + 发送响应
         * @param enable_tcp 是否允许 TCP 命令
         * @param enable_udp 是否允许 UDP 命令
         * @param EnableMux 是否允许 MUX 命令
         * @return 错误码与解析的请求
         * @details 精确分段读取（固定前缀 18B → Addons → 尾部 4B →
         * 地址体），校验 version/addnl/uuid/cmd/atyp。认证失败
         * （UUID 不匹配）不发送响应，静默断开（对齐 Xray）。
         */
        [[nodiscard]] auto ReadHandshake(bool enable_tcp = true, bool enable_udp = true,
                                          bool EnableMux = true)
            -> net::awaitable<std::pair<Error, RequestHeader>>
        {
            // 1. 固定前缀：Version(1) + UUID(16) + AddnlLen(1)
            std::array<std::uint8_t, 18> Prefix{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(Prefix)))
            {
                co_return std::pair{Error::io_error, RequestHeader{}};
            }
            if (Prefix[0] != ProtocolVersion)
            {
                co_return std::pair{Error::bad_magic, RequestHeader{}};
            }

            // 2. Addons（对齐主库：addnl_len 必须为 0）
            if (Prefix[17] != 0)
            {
                co_return std::pair{Error::bad_message, RequestHeader{}};
            }

            // 3. 尾部：Cmd(1) + Port(2 BE) + Atyp(1)
            std::array<std::uint8_t, 4> tail{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(tail)))
            {
                co_return std::pair{Error::io_error, RequestHeader{}};
            }
            const auto cmd = static_cast<Command>(tail[0]);
            if (cmd != Command::Tcp && cmd != Command::Udp && cmd != Command::Mux)
            {
                co_return std::pair{Error::bad_message, RequestHeader{}};
            }
            if ((cmd == Command::Tcp && !enable_tcp) || (cmd == Command::Udp && !enable_udp) ||
                (cmd == Command::Mux && !EnableMux))
            {
                co_return std::pair{Error::not_supported, RequestHeader{}};
            }
            const auto atyp = static_cast<AddressType>(tail[3]);
            if (atyp != AddressType::Ipv4 && atyp != AddressType::Domain && atyp != AddressType::Ipv6)
            {
                co_return std::pair{Error::bad_message, RequestHeader{}};
            }

            // 4. 地址体
            RequestHeader req;
            std::memcpy(req.Uuid.data(), Prefix.data() + 1, UuidLen);
            req.Cmd = cmd;
            req.Target.Type = atyp;
            req.Target.Port = static_cast<std::uint16_t>(tail[1]) << 8 | tail[2];
            auto err = co_await ReadAddressBody(req.Target);
            if (err != Error::none)
            {
                co_return std::pair{err, RequestHeader{}};
            }

            // 5. UUID 校验（memcmp，不匹配则静默断开；可注入认证器）
            const std::string_view got_uuid(reinterpret_cast<const char *>(Prefix.data() + 1), UuidLen);
            const std::string_view expect_uuid(reinterpret_cast<const char *>(uuid_.data()), UuidLen);
            bool bad_auth = false;
            if (auth_)
            {
                bad_auth = !auth_->Check("", got_uuid).Ok;
            }
            else
            {
                bad_auth = (got_uuid != expect_uuid);
            }
            if (bad_auth)
            {
                co_return std::pair{Error::bad_auth, RequestHeader{}};
            }

            // 6. 发送 2 字节响应 [Version 0x00][Addons Length 0x00]
            const auto resp = MakeResponse();
            if (co_await SendBytes(resp))
            {
                co_return std::pair{Error::io_error, RequestHeader{}};
            }

            parsed_ = req;
            handshaken_ = true;
            co_return std::pair{Error::none, std::move(req)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（ReadHandshake 成功后有效）
         */
        [[nodiscard]] auto Parsed() const -> const RequestHeader &
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
            return ReadExactImpl(dst);
        }

    private:
        /**
         * @brief 读取地址体（ATYP 已从尾部解析）
         * @param addr 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        [[nodiscard]] auto ReadAddressBody(Address &addr) -> net::awaitable<Error>
        {
            return Preview::Protocol::Common::ReadAddressBody(
                addr, [this](std::span<std::uint8_t> dst) -> net::awaitable<bool> { return ReadExactImpl(dst); });
        }

        /**
         * @brief 精确读取指定字节数（内部缓冲优先 + 底层补充）
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         */
        [[nodiscard]] auto ReadExactImpl(std::span<std::uint8_t> dst) -> net::awaitable<bool>
        {
            std::size_t Done = 0;
            while (Done < dst.size())
            {
                if (used_ > 0)
                {
                    const auto n = std::min(dst.size() - Done, used_);
                    std::memcpy(dst.data() + Done, buf_.data(), n);
                    if (n < used_)
                    {
                        std::memmove(buf_.data(), buf_.data() + n, used_ - n);
                        used_ -= n;
                    }
                    else
                    {
                        buf_.clear();
                        used_ = 0;
                    }
                    Done += n;
                    continue;
                }
                std::array<std::uint8_t, 512> chunk{};
                std::error_code ec;
                const auto n = co_await next_layer_->AsyncReadSome(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(chunk.data()), chunk.size()), ec);
                if (ec || n == 0)
                {
                    co_return true;
                }
                buf_.insert(buf_.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(n));
                used_ += n;
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
                const auto n = co_await next_layer_->AsyncWriteSome(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data() + Done),
                                               Data.size() - Done),
                    ec);
                if (ec)
                {
                    co_return true;
                }
                Done += n;
            }
            co_return false;
        }

        SharedTransmission next_layer_;          ///< 上游传输（独占所有权）
        std::array<std::uint8_t, UuidLen> uuid_; ///< 协议 UUID（凭据/校验）
        const Preview::Authenticator *auth_{nullptr}; ///< 认证器（非拥有）
        RequestHeader parsed_;                   ///< 服务端握手解析结果
        Memory mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename std::template Buffer<std::uint8_t> buf_{mem_.Arena()}; ///< 预读缓冲（隧道数据暂存）
        std::size_t used_{0};                     ///< 缓冲中有效字节数
        bool handshaken_{false};         ///< 握手完成标志
    };


    /// 流连接共享指针
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Vless
