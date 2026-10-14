/**
 * @file Conn.hpp
 * @brief TUIC 会话连接公共聚合入口。
 * @details Conn 只保留原有 Transmission、认证、Connect 握手和 packet API，
 *          具体职责由 ConnSession、ConnIo、ConnAuth、ConnStream 和
 *          ConnDatagram 分别拥有。底层传输、认证租约与会话内存仍由连接
 *          生命周期统一持有。
 * @note 实例非线程安全，应在同一协程或线程内使用。
 */
#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Account/Lease.hpp>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Memory/Pointer.hpp>
#include <Preview/Protocols/Tuic/ConnAuth.hpp>
#include <Preview/Protocols/Tuic/ConnDatagram.hpp>
#include <Preview/Protocols/Tuic/ConnIo.hpp>
#include <Preview/Protocols/Tuic/ConnSession.hpp>
#include <Preview/Protocols/Tuic/ConnStream.hpp>
#include <Preview/Protocols/Tuic/Types.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Preview::Tuic
{

    namespace Net = boost::asio;

    /**
     * @class Conn
     * @brief TUIC 会话连接（Transmission 装饰器）。
     * @tparam Memory 会话内存策略
     * @details 对外 API 保持稳定；连接级资源和状态由 ConnSession 持有，
     *          方法实现委托给对应的职责 owner。
     */
    template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
    class Conn : public Preview::Transmission
    {
    public:
        explicit Conn(
            SharedTransmission Upstream,
            std::array<std::uint8_t, UuidLen> Uuid,
            Preview::SharedAuthenticator AuthOwner = {})
            : Preview::Transmission(Upstream ? Upstream->Executor() : Net::any_io_executor{}),
              Session_(std::move(Upstream), Uuid, std::move(AuthOwner)),
              Io_(Session_),
              Authenticator_(Session_),
              Stream_(Session_, Io_),
              Datagram_(Session_, Io_)
        {
        }

        Conn(const Conn &) = delete;
        auto operator=(const Conn &) -> Conn & = delete;

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Io_.Executor();
        }

        /** @brief 在独立 uni stream 发送 TUIC exporter 认证帧。 */
        [[nodiscard]] auto WriteAuthentication(
            SharedTransmission AuthStream,
            const KeyingMaterialExporter &Exporter,
            std::string_view Password) -> Net::awaitable<Error>
        {
            return Authenticator_.WriteAuthentication(
                std::move(AuthStream), Exporter, Password);
        }

        /** @brief 在独立 uni stream 校验 TUIC exporter 和 typed credential。 */
        [[nodiscard]] auto ReadAuthentication(
            SharedTransmission AuthStream,
            ServerAuthenticationMaterial Material) -> Net::awaitable<Error>
        {
            return Authenticator_.ReadAuthentication(
                std::move(AuthStream), std::move(Material));
        }

        [[nodiscard]] auto TakeAuthLease() -> Preview::Account::AccountLease
        {
            return Authenticator_.TakeAuthLease();
        }

        [[nodiscard]] auto AccountId() const noexcept -> Preview::AccountId
        {
            return Authenticator_.AccountId();
        }

        [[nodiscard]] auto Identity() const noexcept -> std::string_view
        {
            return Authenticator_.Identity();
        }

        /** @brief 复用已完成的连接级认证结果接入后续 bidi stream。 */
        auto MarkAuthenticated(
            Preview::AccountId AccountId = {},
            Preview::Account::AccountLease Lease = {},
            std::string Identity = {}) -> void
        {
            Authenticator_.MarkAuthenticated(
                AccountId, std::move(Lease), std::move(Identity));
        }

        /** @brief 客户端发送 Connect frame。 */
        [[nodiscard]] auto WriteHandshake(const Address &Target)
            -> Net::awaitable<Error>
        {
            return Stream_.WriteHandshake(Target);
        }

        /** @brief 服务端读取 Connect frame。 */
        [[nodiscard]] auto ReadHandshake()
            -> Net::awaitable<std::pair<Error, Message>>
        {
            return Stream_.ReadHandshake();
        }

        [[nodiscard]] auto Parsed() const noexcept -> const Message &
        {
            return Stream_.Parsed();
        }

        /** @brief 发送一个连接级 packet 数据报。 */
        [[nodiscard]] auto AsyncSendDatagram(
            const Address &Target,
            std::span<const std::uint8_t> Payload) -> Net::awaitable<Error>
        {
            return Datagram_.AsyncSendDatagram(Target, Payload);
        }

        /** @brief 接收一个连接级 packet 数据报。 */
        [[nodiscard]] auto AsyncReceiveDatagram(
            Address &Target,
            std::vector<std::uint8_t> &Payload) -> Net::awaitable<Error>
        {
            return Datagram_.AsyncReceiveDatagram(Target, Payload);
        }

        /** @brief 握手后的 partial read；结果与借用沿正式前门交付一次。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<TuicReadWork>(TuicRead{std::static_pointer_cast<Conn>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /** @brief 握手后的 partial write，保留底层 short write 语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<TuicWriteWork>(TuicWrite{std::static_pointer_cast<Conn>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层连接；读取方向保持可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Io_.WriteShutdown(std::move(Handler));
        }

        /** @brief 清除连接状态并关闭底层传输；实际退出由 Activity()->Drain() 等待。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            return Io_.Close();
        }

        /** @brief 只取消底层挂起操作，保留连接状态。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Io_.Cancel();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return Io_.NextLayer();
        }

        [[nodiscard]] auto NextLayer() const noexcept
            -> const Preview::Transmission * override
        {
            return Io_.NextLayer();
        }

        /** @brief 释放底层传输并清理连接级租约。 */
        [[nodiscard]] auto Release() -> Preview::SharedTransmission override
        {
            return Io_.Release();
        }

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Io_.HasUpstream() && Session_.IsHandshaken();
        }

        [[nodiscard]] auto Underlying() noexcept -> Preview::SharedTransmission
        {
            return Io_.Underlying();
        }

        [[nodiscard]] auto Arena() noexcept -> Preview::Memory::ResourcePointer
        {
            return Session_.Arena();
        }

    private:
        using Session = detail::ConnSession<Memory>;
        using Io = detail::ConnIo<Memory>;
        using AuthenticatorOwner = detail::ConnAuth<Memory>;
        using Stream = detail::ConnStream<Memory>;
        using Datagram = detail::ConnDatagram<Memory>;

        struct TuicRead final { std::shared_ptr<Conn> Owner; std::span<std::byte> Buffer; };
        struct TuicWrite final { std::shared_ptr<Conn> Owner; std::span<const std::byte> Buffer; };
        struct TuicReadWork final
        {
            template<class State>
            auto operator()(State Operation, TuicRead Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Preview::IoResult{0, {Preview::Fault::Code::InvalidArgument}}};
                co_return std::tuple{co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->Stream_.ReadSome(Input.Buffer), Net::deferred)};
            }
        };
        struct TuicWriteWork final
        {
            template<class State>
            auto operator()(State Operation, TuicWrite Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Preview::IoResult{0, {Preview::Fault::Code::InvalidArgument}}};
                co_return std::tuple{co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->Stream_.WriteSome(Input.Buffer), Net::deferred)};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        Session Session_;
        Io Io_;
        AuthenticatorOwner Authenticator_;
        Stream Stream_;
        Datagram Datagram_;
    };

    /// TUIC 流连接共享指针。
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Preview::TransmissionLike<Conn<>>);

} // namespace Preview::Tuic
