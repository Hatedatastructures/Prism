/**
 * @file Conn.hpp
 * @brief SOCKS5 流连接的正式 Transmission 载体
 * @details 构造时接管上游并由 ConnTransport 持有传输路径，异步操作使用上游 executor。
 *          Cancel 转交上游控制 owner；WriteShutdown 只半关闭写方向，反向读取继续可用；
 *          Close 交付最终关闭，Activity::Drain 确认实际 I/O 退栈。
 *          RFC1929 认证及账户租约由 ConnAuth 拥有，握手/请求状态由 ConnHandshake 拥有。
 *          UDP 关联服务由 UdpAssoc.hpp 独立拥有。
 */

#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <expected>

#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Socks5/ConnAuth.hpp>
#include <Prism/Protocols/Socks5/ConnHandshake.hpp>
#include <Prism/Protocols/Socks5/ConnTransport.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Socks5
{

    /**
     * @class Conn
     * @brief SOCKS5 流连接 owner
     * @tparam Memory 会话内存策略
     * @details 构造时接管底层 SharedTransmission；异步操作沿 ConnTransport executor 执行。
     *          Cancel 转交上游控制 owner，WriteShutdown 保留反向读取，Close 交付最终关闭。
     */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    class Conn : public Prism::Transmission
    {
    public:
        using MemoryType = Memory;

        /** @brief 接管底层传输所有权。 */
        explicit Conn(SharedTransmission Upstream)
            : Prism::Transmission(Upstream ? Upstream->Executor() : Net::any_io_executor{}),
              Mem_{}, Transport_(std::move(Upstream), Mem_), Handshake_(Mem_)
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            const auto Value = Transport_.Executor();
            return Value ? Value : Prism::Transmission::Executor();
        }

        /** @brief 预读缓冲优先的部分读取；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Transport_.ReadSome(Buffer, std::move(Handler));
        }

        /** @brief 异步部分写入，保持底层短写语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Transport_.WriteSome(Buffer, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层；读取方向仍然可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Transport_.WriteShutdown(std::move(Handler));
        }

        /** @brief 封止并交付底层关闭；实际退出由 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return Transport_.Close();
        }

        /** @brief 可重复取消底层 I/O；成功只表示命令已接管，不宣称已经关闭。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Transport_.Cancel();
        }

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Transport_.HasUpstream() && Handshake_.IsHandshaken();
        }

        [[nodiscard]] auto Underlying() noexcept -> SharedTransmission
        {
            return Transport_.Underlying();
        }

        [[nodiscard]] auto Underlying() const noexcept -> SharedTransmission
        {
            return Transport_.Underlying();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return Transport_.NextLayer();
        }

        [[nodiscard]] auto NextLayer() const noexcept
            -> const Prism::Transmission * override
        {
            return Transport_.NextLayer();
        }

        [[nodiscard]] auto Release() -> SharedTransmission override
        {
            return Transport_.Release();
        }

        /** @brief 客户端完整握手。 */
        [[nodiscard]] auto WriteHandshake(
            const Prism::Socks5::Request &RequestValue,
            const ClientConfig &Config)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            using HandshakeRequest = typename ConnHandshake<Memory>::WriteHandshakeRequest;
            return Handshake_.WriteHandshake(HandshakeRequest{
                Transport_, Auth_, RequestValue, Config});
        }

        /** @brief 服务端完整握手并返回解析请求。 */
        [[nodiscard]] auto ReadHandshake(const ServerConfig &Config)
            -> Net::awaitable<std::expected<Prism::Socks5::Request, Prism::Fault::Failure>>
        {
            return Handshake_.ReadHandshake(Transport_, Auth_, Config);
        }

        [[nodiscard]] auto Parsed() const -> const Prism::Socks5::Request &
        {
            return Handshake_.Parsed();
        }

        [[nodiscard]] auto BindEndpoint() const -> const Address &
        {
            return Handshake_.BindEndpoint();
        }

        /** @brief 转移协议认证产生的账户租约。 */
        [[nodiscard]] auto TakeAuthLease() -> Prism::Account::AccountLease
        {
            return Auth_.TakeAuthLease();
        }

        [[nodiscard]] auto AccountId() const noexcept -> Prism::AccountId
        {
            return Auth_.AccountId();
        }

        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Auth_.Identity();
        }

        [[nodiscard]] auto DisplayIdentity() const noexcept -> std::string_view
        {
            return Auth_.DisplayIdentity();
        }

        /** @brief 发送延迟 CONNECT 应答。 */
        [[nodiscard]] auto SendConnectReply(ReplyCode Code) const
            -> Net::awaitable<ReplyResult<std::size_t>>
        {
            return Handshake_.SendConnectReply(Transport_, Code);
        }

        /**
         * @brief 发送带 BND 地址的 UDP_ASSOCIATE 应答。
         * @param Code 按值传入的 SOCKS5 回复码。
         * @param Bind 按值拥有的 BND 地址；暂停期间不借用调用者的对象。
         * @return 完整 wire 字节或协议码、Native cause 与 partial progress。
         * @note ConnHandshake 持有 wire 缓冲至 WriteSome completion；调用者须串行化该方向写。
         */
        [[nodiscard]] auto SendAssocReply(
            ReplyCode Code,
            Address Bind) -> Net::awaitable<ReplyResult<std::size_t>>
        {
            return Handshake_.SendAssocReply(Transport_, Code, std::move(Bind));
        }

    private:
        Memory Mem_;
        ConnTransport<Memory> Transport_;
        ConnAuth<Memory> Auth_;
        ConnHandshake<Memory> Handshake_;
    };

    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Prism::TransmissionLike<Conn<>>);

} // namespace Prism::Socks5
