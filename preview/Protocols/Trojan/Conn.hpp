/**
 * @file Conn.hpp
 * @brief Trojan 流连接对象（装饰器模式：内存策略模板化）
 * @details 单条 TCP 协议连接的完整状态：持有上游传输（所有权，
 * SharedTransmission 运行时多态）、预读缓冲、凭据。读写经虚接口
 * 静态委托给上游具体传输（内存流 / 可靠连接均满足 TransmissionLike）。
 * - 客户端：WriteHandshake 发送请求头（凭据 + 命令 + 地址）
 * - 服务端：ReadHandshake 解析校验请求头
 * UDP 数据面由 Dgram.hpp 提供（独立包连接类型，嵌入本连接）。
 * @note 对齐 mihomo transport：TCP = net.Conn（纯流语义）。
 * @note 模板参数仅 Memory（会话内存策略：Arena 复用零分配），
 *      上游传输类型经 Transmission 虚接口擦除，装饰器链统一。
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
#include <string_view>
#include <utility>
#include <vector>

#include <preview/Foundation/Authenticator.hpp>
#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Pointer.hpp>
#include <preview/Protocols/Common/Address.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Protocols/Trojan/Codec.hpp>
#include <preview/Protocols/Trojan/Types.hpp>

namespace Preview::Trojan
{

    /**
     * @class Conn
     * @brief Trojan 流连接对象（装饰器模式）
     * @tparam Memory 会话内存策略（默认 8KB Arena）
     * @details 单条 TCP 连接的协议状态：握手（客户端写 / 服务端读）、
     * 数据透传、预读缓冲。读写经传输虚接口委托上游具体类型。
     * 由工厂（Connect / Accept）创建，调用方以 shared_ptr 持有。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission, public std::enable_shared_from_this<Conn<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param upstream 上游传输（所有权移交）
         * @param password 协议密码（派生 SHA224 hex 凭据）
         * @param Auth 认证器（非拥有；nullptr = 静态比对 password）
         */
        explicit Conn(SharedTransmission upstream, std::string password,
                      const Preview::Authenticator *Auth = nullptr)
            : NextLayer_(std::move(upstream)), Auth_(Auth)
        {
            Cred_ = Credential(password);
        }

        /**
         * @brief 获取执行器（静态分派到上游）
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
         * @details 握手阶段预读的剩余字节先被消费，清空后透传底层。
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
         * @brief 异步写入（静态分派透传）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await NextLayer_->async_write_some(Buffer, ec);
        }

        /**
         * @brief 异步读取直至缓冲区读满（组合操作）
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数（满 = Buffer.size()；EOF 提前返回）
         */
        [[nodiscard]] auto AsyncRead(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                const auto N = co_await async_read_some(Buffer.subspan(Done), ec);
                if (ec)
                {
                    co_return Done;
                }
                if (N == 0)
                {
                    co_return Done;
                }
                Done += N;
            }
            co_return Done;
        }

        /**
         * @brief 异步写入直至缓冲区写满（组合操作）
         * @param Buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入字节数（满 = Buffer.size()）
         */
        [[nodiscard]] auto AsyncWrite(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                const auto N = co_await async_write_some(Buffer.subspan(Done), ec);
                if (ec)
                {
                    co_return Done;
                }
                if (N == 0)
                {
                    ec = make_error_code(Error::BrokenPipe);
                    co_return Done;
                }
                Done += N;
            }
            co_return Done;
        }

        /**
         * @brief 关闭传输层（静态分派）
         */
        void Close() override
        {
            NextLayer_->Close();
        }

        /**
         * @brief 取消挂起操作（静态分派）
         */
        void Cancel() override
        {
            NextLayer_->Cancel();
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         */
        [[nodiscard]] auto NextLayer() noexcept 
            -> Preview::Transmission * override
        {
            return NextLayer_.get();
        }

        /**
         * @brief 获取内层传输（const 版本）
         */
        [[nodiscard]] auto NextLayer() const noexcept 
            -> const Preview::Transmission * override
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
         * @brief 客户端握手：发送请求头（凭据 + 命令 + 地址）
         * @param Target 目标地址
         * @param cmd 命令（CONNECT / udp_associate / mux）
         * @return 错误码
         * @details 构造并发送请求头，不读响应（对齐主库 trojan）。
         * 由工厂 Connect 内部调用。
         */
        [[nodiscard]] auto WriteHandshake(const Address &Target, Command Cmd = Command::Connect)
            -> net::awaitable<Error>
        {
            const auto Wire = BuildRequest(Cred_, Cmd, Target);
            const bool Failed = co_await SendBytes(Wire); // true = 发送失败
            Handshaken_ = !Failed;
            if (Failed)
            {
                co_return Error::IoError;
            }
            co_return Error::None;
        }

        /**
         * @brief 服务端握手：解析请求头
         * @param EnableTcp 是否允许 CONNECT 命令
         * @param EnableUdp 是否允许 UDP_ASSOCIATE 命令
         * @return 错误码与解析的请求
         * @details 精确分段读取并校验（凭据/CRLF/命令开关/atyp/尾部）。
         * 认证失败不发送响应，静默断开（对齐 trojan-gfw）。
         * 由工厂 Accept 内部调用。
         */
        [[nodiscard]] auto ReadHandshake(bool EnableTcp = true, bool EnableUdp = false)
            -> net::awaitable<std::pair<Error, RequestHeader>>
        {
            // 1. 凭据前缀：Credential(56) + CRLF(2)
            std::array<std::uint8_t, CredentialLen + 2> Prefix{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(Prefix)))
            {
                co_return std::pair{Error::IoError, RequestHeader{}};
            }
            const std::string_view got(reinterpret_cast<const char *>(Prefix.data()), CredentialLen);
            bool BadAuth = false;
            if (Auth_)
            {
                BadAuth = !Auth_->Check("", got).Ok;
            }
            else
            {
                BadAuth = (got != Cred_);
            }
            if (BadAuth)
            {
                co_return std::pair{Error::BadAuth, RequestHeader{}};
            }
            if (Prefix[CredentialLen] != '\r' || Prefix[CredentialLen + 1] != '\n')
            {
                co_return std::pair{Error::BadMagic, RequestHeader{}};
            }

            // 2. 头部：Cmd(1) + Atyp(1)
            std::array<std::uint8_t, 2> head{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(head)))
            {
                co_return std::pair{Error::IoError, RequestHeader{}};
            }
            const auto Cmd = static_cast<Command>(head[0]);
            if (Cmd != Command::Connect && Cmd != Command::UdpAssociate && Cmd != Command::Mux)
            {
                co_return std::pair{Error::BadMessage, RequestHeader{}};
            }
            if (Cmd == Command::Connect && !EnableTcp)
            {
                co_return std::pair{Error::NotSupported, RequestHeader{}};
            }
            if (Cmd == Command::UdpAssociate && !EnableUdp)
            {
                co_return std::pair{Error::NotSupported, RequestHeader{}};
            }
            const auto Atyp = static_cast<AddressType>(head[1]);
            if (Atyp != AddressType::Ipv4 && Atyp != AddressType::Domain && Atyp != AddressType::Ipv6)
            {
                co_return std::pair{Error::BadMessage, RequestHeader{}};
            }

            // 3. 地址体
            RequestHeader req;
            req.Cmd = Cmd;
            req.Target.Type = Atyp;
            auto Err = co_await ReadAddressBody(req.Target);
            if (Err != Error::None)
            {
                co_return std::pair{Err, RequestHeader{}};
            }

            // 4. 尾部：Port(2 BE) + CRLF(2)
            std::array<std::uint8_t, 4> tail{};
            if (co_await ReadExactImpl(std::span<std::uint8_t>(tail)))
            {
                co_return std::pair{Error::IoError, RequestHeader{}};
            }
            req.Target.Port = static_cast<std::uint16_t>(tail[0]) << 8 | tail[1];
            if (tail[2] != '\r' || tail[3] != '\n')
            {
                co_return std::pair{Error::BadMagic, RequestHeader{}};
            }

            Request_ = req;
            Handshaken_ = true;
            co_return std::pair{Error::None, std::move(req)};
        }

        /**
         * @brief 获取服务端握手解析的请求
         * @return 请求（ReadHandshake 成功后有效）
         */
        [[nodiscard]] auto Request() const -> const RequestHeader &
        {
            return Request_;
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
         * @brief 读取地址体（ATYP 已由调用方解析）
         * @param addr 输出地址
         * @return 错误码
         * @note 转发层：统一实现见 Protocol/common::ReadAddressBody
         */
        [[nodiscard]] auto ReadAddressBody(Address &addr)
            -> net::awaitable<Error>
        {
            return Preview::Protocol::Common::ReadAddressBody(
                addr, [this](std::span<std::uint8_t> dst) -> net::awaitable<bool> { return ReadExactImpl(dst); });
        }

        /**
         * @brief 精确读取指定字节数（内部缓冲优先 + 底层补充）
         * @param dst 目标缓冲区
         * @return true = 失败（EOF / 底层错误）
         * @details 超读字节保留在内部缓冲供后续消费。
         */
        [[nodiscard]] auto ReadExactImpl(std::span<std::uint8_t> dst) 
            -> net::awaitable<bool>
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

        SharedTransmission NextLayer_;              ///< 上游传输（基类传参，运行时多态）
        std::string Cred_;                            ///< 预计算凭据（SHA224 hex）
        const Preview::Authenticator *Auth_{nullptr}; ///< 认证器（非拥有）
        RequestHeader Request_;                      ///< 服务端握手解析结果
        Memory Mem_;                                  ///< 会话内存策略（Arena，热路径零释放分配）
        typename Memory::template Buffer<std::uint8_t> Buf_{Mem_.Arena()}; ///< 预读缓冲（隧道数据暂存）
        std::size_t Used_{0};                                              ///< 缓冲中有效字节数
        bool Handshaken_{false};                                           ///< 握手完成标志
    };

    /// 流连接共享指针
    using SharedConn = std::shared_ptr<Conn<>>;

    // 编译期验证：Conn 满足传输接口概念（可被其他协议工厂接收）
    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Trojan
