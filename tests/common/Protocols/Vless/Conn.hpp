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
            : NextLayer_(std::move(upstream)), Uuid_(uuid), Auth_(Auth)
        {
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return NextLayer_->Executor();
        }

        /**
         * @brief 异步读取（预读缓冲优先）
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            ec.clear();
            if (Used_ > 0)
            {
                const auto N = std::min(Buffer.size(), Used_);
                std::memcpy(Buffer.data(), Buf_.data(), N);
                if (N < Used_)
                {
                    std::memmove(Buf_.data(), Buf_.data() + N, Used_ - N);
                }
                else
                {
                    Buf_.clear();
                }
                Used_ -= N;
                co_return N;
            }
            co_return co_await NextLayer_->async_read_some(Buffer, ec);
        }

        /**
         * @brief 异步写入（透传）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await NextLayer_->async_write_some(Buffer, ec);
        }

        /**
         * @brief 关闭传输层
         */
        void Close() override
        {
            if (NextLayer_)
            {
                NextLayer_->Close();
            }
        }

        /**
         * @brief 取消挂起操作
         */
        void Cancel() override
        {
            if (NextLayer_)
            {
                NextLayer_->Cancel();
            }
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return std::move(NextLayer_);
        }
        /**
         * @brief 会话是否有效（已握手且底层存在）
         * @return 有效返回 true
         */
        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return NextLayer_ != nullptr && Handshaken_;
        }

        /**
         * @brief 获取底层传输引用（非拥有）
         * @return 底层传输
         */
        [[nodiscard]] auto Underlying() noexcept -> SharedTransmission
        {
            return NextLayer_;
        }

        /**
         * @brief 获取会话级内存竞技场
         * @return 非拥有资源指针（供握手/解析的临时分配）
         * @note 分配的对象随 Conn 存活，Conn 析构时一次性回收
         */
        [[nodiscard]] auto Arena() noexcept -> Preview::Memory::ResourcePointer
        {
            return Mem_.Arena();
        }

        /**
         * @brief 客户端握手：发送请求头 + 读取 2 字节响应
         * @param Target 目标地址
         * @param cmd 命令（默认 Tcp；UDP 场景传 udp）
         * @return 错误码
         * @details 构造请求头（version/uuid/cmd/Target）发送，
         * 读取 2 字节响应校验 Version 回显（对齐 Xray）。
         */
        [[nodiscard]] auto WriteHandshake(const Address &Target, Command Cmd = Command::Tcp)
            -> net::awaitable<Error>
        {
            RequestHeader hdr;
            hdr.Version = ProtocolVersion;
            hdr.Uuid = Uuid_;
            hdr.Cmd = Cmd;
            hdr.Target = Target;
            const auto Wire = BuildRequest(hdr);
            if (co_await SendBytes(Wire))
            {
                co_return Error::IoError;
            }

            std::array<std::uint8_t, 2> Resp{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(Resp)))
            {
                co_return Error::IoError;
            }
            if (Resp[0] != ProtocolVersion)
            {
                co_return Error::BadMagic;
            }
            Handshaken_ = true;
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：四段解析请求头 + 校验 + 发送响应
         * @param EnableTcp 是否允许 TCP 命令
         * @param EnableUdp 是否允许 UDP 命令
         * @param EnableMux 是否允许 MUX 命令
         * @return 错误码与解析的请求
         * @details 精确分段读取（固定前缀 18B → Addons → 尾部 4B →
         * 地址体），校验 version/addnl/uuid/cmd/atyp。认证失败
         * （UUID 不匹配）不发送响应，静默断开（对齐 Xray）。
         */
        [[nodiscard]] auto ReadHandshake(bool EnableTcp = true, bool EnableUdp = true,
                                          bool EnableMux = true)
            -> net::awaitable<std::pair<Error, RequestHeader>>
        {
            // 1. 固定前缀：Version(1) + UUID(16) + AddnlLen(1)
            std::array<std::uint8_t, 18> Prefix{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(Prefix)))
            {
                co_return std::pair{Error::IoError, RequestHeader{}};
            }
            if (Prefix[0] != ProtocolVersion)
            {
                co_return std::pair{Error::BadMagic, RequestHeader{}};
            }

            // 2. Addons（对齐主库：AddnlLen 必须为 0）
            if (Prefix[17] != 0)
            {
                co_return std::pair{Error::BadMessage, RequestHeader{}};
            }

            // 3. 尾部：Cmd(1) + Port(2 BE) + Atyp(1)
            std::array<std::uint8_t, 4> tail{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(tail)))
            {
                co_return std::pair{Error::IoError, RequestHeader{}};
            }
            const auto Cmd = static_cast<Command>(tail[0]);
            if (Cmd != Command::Tcp && Cmd != Command::Udp && Cmd != Command::Mux)
            {
                co_return std::pair{Error::BadMessage, RequestHeader{}};
            }
            if ((Cmd == Command::Tcp && !EnableTcp) || (Cmd == Command::Udp && !EnableUdp) ||
                (Cmd == Command::Mux && !EnableMux))
            {
                co_return std::pair{Error::NotSupported, RequestHeader{}};
            }
            const auto Atyp = static_cast<AddressType>(tail[3]);
            if (Atyp != AddressType::Ipv4 && Atyp != AddressType::Domain && Atyp != AddressType::Ipv6)
            {
                co_return std::pair{Error::BadMessage, RequestHeader{}};
            }

            // 4. 地址体
            RequestHeader req;
            std::memcpy(req.Uuid.data(), Prefix.data() + 1, UuidLen);
            req.Cmd = Cmd;
            req.Target.Type = Atyp;
            req.Target.Port = static_cast<std::uint16_t>(tail[1]) << 8 | tail[2];
            auto Err = co_await ReadAddressBody(req.Target);
            if (Err != Error::None)
            {
                co_return std::pair{Err, RequestHeader{}};
            }

            // 5. UUID 校验（memcmp，不匹配则静默断开；可注入认证器）
            const std::string_view GotUuid(reinterpret_cast<const char *>(Prefix.data() + 1), UuidLen);
            const std::string_view expect_uuid(reinterpret_cast<const char *>(Uuid_.data()), UuidLen);
            bool BadAuth = false;
            if (Auth_)
            {
                BadAuth = !Auth_->Check("", GotUuid).Ok;
            }
            else
            {
                BadAuth = (GotUuid != expect_uuid);
            }
            if (BadAuth)
            {
                co_return std::pair{Error::BadAuth, RequestHeader{}};
            }

            // 6. 发送 2 字节响应 [Version 0x00][Addons Length 0x00]
            const auto Resp = MakeResponse();
            if (co_await SendBytes(Resp))
            {
                co_return std::pair{Error::IoError, RequestHeader{}};
            }

            Parsed_ = req;
            Handshaken_ = true;
            co_return std::pair{Error::None, std::move(req)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（ReadHandshake 成功后有效）
         */
        [[nodiscard]] auto Parsed() const -> const RequestHeader &
        {
            return Parsed_;
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
                if (Used_ > 0)
                {
                    const auto N = std::min(dst.size() - Done, Used_);
                    std::memcpy(dst.data() + Done, Buf_.data(), N);
                    if (N < Used_)
                    {
                        std::memmove(Buf_.data(), Buf_.data() + N, Used_ - N);
                        Used_ -= N;
                    }
                    else
                    {
                        Buf_.clear();
                        Used_ = 0;
                    }
                    Done += N;
                    continue;
                }
                std::array<std::uint8_t, 512> chunk{};
                std::error_code ec;
                const auto N = co_await NextLayer_->async_read_some(
                    std::span<std::byte>(reinterpret_cast<std::byte *>(chunk.data()), chunk.size()), ec);
                if (ec || N == 0)
                {
                    co_return true;
                }
                Buf_.insert(Buf_.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(N));
                Used_ += N;
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
                const auto N = co_await NextLayer_->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(Data.data() + Done),
                                               Data.size() - Done),
                    ec);
                if (ec)
                {
                    co_return true;
                }
                if (N == 0)
                {
                    co_return true; // 底层零字节写入，防死循环
                }
                Done += N;
            }
            co_return false;
        }

        SharedTransmission NextLayer_;          ///< 上游传输（独占所有权）
        std::array<std::uint8_t, UuidLen> Uuid_; ///< 协议 UUID（凭据/校验）
        const Preview::Authenticator *Auth_{nullptr}; ///< 认证器（非拥有）
        RequestHeader Parsed_;                   ///< 服务端握手解析结果
        Memory Mem_;                     ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> Buf_{Mem_.Arena()}; ///< 预读缓冲（隧道数据暂存）
        std::size_t Used_{0};                     ///< 缓冲中有效字节数
        bool Handshaken_{false};         ///< 握手完成标志
    };


    /// 流连接共享指针
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Vless
