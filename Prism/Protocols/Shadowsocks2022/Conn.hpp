/**
 * @file Conn.hpp
 * @brief Shadowsocks 2022 客户端/服务端流连接公共聚合入口。
 * @details 公共 Transmission API 由显式 executor 绑定；握手、加密 record、UDP
 *          数据面和会话资源分别由专用 owner 实现，避免连接头同时承担四种职责。
 * @note 实例非线程安全，应在同一协程或线程内使用。
 */
#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnDatagram.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnHandshake.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnOptions.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnRecord.hpp>
#include <Prism/Protocols/Shadowsocks2022/ConnSession.hpp>
#include <Prism/Protocols/Shadowsocks2022/Types.hpp>

namespace Prism::Shadowsocks2022
{

    namespace Net = boost::asio;
    namespace ss = Prism::Shadowsocks2022;

    /**
     * @class Conn
     * @brief SS2022 流连接装饰器。
     * @tparam Memory 会话内存策略
     * @details 该类只保留正式协议 API 和 owner 之间的委托。底层传输所有权、
     *          PSK、认证租约及会话缓冲由 ConnSession 持有。
     */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    class Conn : public Prism::Transmission
    {
    public:
        explicit Conn(ConnOptions Options)
            : Prism::Transmission(Options.Executor),
              Session_(std::move(Options)),
              Record_(Session_),
              Handshake_(Session_, Record_),
              Datagram_(Session_, Record_)
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Session_.Executor();
        }

        /** @brief 部分读取；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Record_.ReadSome(Buffer, std::move(Handler));
        }

        /** @brief 部分写入；保留 chunk 加密与短写语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Record_.WriteSome(Buffer, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层载体；反向读取仍然可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Record_.WriteShutdown(std::move(Handler));
        }

        /** @brief 封止并交付底层关闭；实际退出由 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return Session_.Close();
        }

        /** @brief 可重复取消底层挂起操作；成功只表示命令已接管。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Session_.Cancel();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return Session_.NextLayer_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept
            -> const Prism::Transmission * override
        {
            return Session_.NextLayer_.get();
        }

        [[nodiscard]] auto Release() -> Prism::SharedTransmission override
        {
            return std::move(Session_.NextLayer_);
        }

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Session_.NextLayer_ != nullptr && Session_.Handshaken_;
        }

        [[nodiscard]] auto Underlying() noexcept -> Prism::SharedTransmission
        {
            return Session_.NextLayer_;
        }

        [[nodiscard]] auto Arena() noexcept -> Prism::Memory::ResourcePointer
        {
            return Session_.Mem_.Arena();
        }

        [[nodiscard]] auto WriteHandshake(
            Prism::SharedTransmission Upstream,
            const ss::Address &Target)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            co_return co_await Handshake_.WriteHandshake(std::move(Upstream), Target);
        }

        [[nodiscard]] auto AsyncSendDatagram(
            const ss::Address &Target,
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            co_return co_await Datagram_.AsyncSendDatagram(Target, Payload);
        }

        [[nodiscard]] auto AsyncReceiveDatagram(
            ss::Address &Target,
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            co_return co_await Datagram_.AsyncReceiveDatagram(Target, Payload);
        }

        [[nodiscard]] auto ReadHandshake(Prism::SharedTransmission Upstream)
            -> Net::awaitable<std::expected<ss::Message, Prism::Fault::Failure>>
        {
            co_return co_await Handshake_.ReadHandshake(std::move(Upstream));
        }

        [[nodiscard]] auto Parsed() const -> const ss::Message &
        {
            return Handshake_.Parsed();
        }

        [[nodiscard]] auto TakeAuthLease() -> Prism::Account::AccountLease
        {
            return Handshake_.TakeAuthLease();
        }

        [[nodiscard]] auto AccountId() const noexcept -> Prism::AccountId
        {
            return Handshake_.AccountId();
        }

        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Handshake_.Identity();
        }

    private:
        using Session = detail::ConnSession<Memory>;
        using Record = detail::ConnRecord<Memory>;
        using Handshake = detail::ConnHandshake<Memory>;
        using Datagram = detail::ConnDatagram<Memory>;

        Session Session_;
        Record Record_;
        Handshake Handshake_;
        Datagram Datagram_;
    };

    /// 流连接共享指针。
    using SharedConn = std::shared_ptr<Conn<>>;

} // namespace Prism::Shadowsocks2022
