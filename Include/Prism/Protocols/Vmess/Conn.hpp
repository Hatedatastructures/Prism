/**
 * @file Conn.hpp
 * @brief VMess 流连接的公共聚合入口。
 * @details Conn 只保留显式 executor 绑定的 Transmission 接口和四个职责 owner 的生命周期：
 *          ConnSession、ConnIo、ConnChunk 与 ConnHandshake。协议线上的认证、
 *          chunk 加解密、partial I/O、close/cancel 和账户租约语义保持不变。
 * @note 实例非线程安全，应在同一协程或线程内使用。
 */
#pragma once
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Protocols/Vmess/AuthHeader.hpp>
#include <Prism/Protocols/Vmess/ConnChunk.hpp>
#include <Prism/Protocols/Vmess/ConnHandshake.hpp>
#include <Prism/Protocols/Vmess/ConnIo.hpp>
#include <Prism/Protocols/Vmess/ConnSession.hpp>
#include <Prism/Contract/Io/PacketTransferResult.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/this_coro.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>
#include <cstddef>
#include <tuple>

namespace Prism::Vmess
{

    namespace Net = boost::asio;

    namespace detail
    {
        /** @brief VMess wrapper 自身及已接管 carrier 的真实关闭/排空回执。 */
        class ConnActivity final : public Prism::Contract::CarrierActivity,
                                   public std::enable_shared_from_this<ConnActivity>
        {
        public:
            explicit ConnActivity(std::shared_ptr<Prism::Contract::CarrierActivity> Parent)
                : Parent_(std::move(Parent))
            {
            }

            auto AttachChild(std::shared_ptr<Prism::Contract::CarrierActivity> Child) noexcept
                -> void
            {
                Child_.store(std::move(Child), std::memory_order_release);
            }

            auto ClearChild() noexcept -> void
            {
                ChildDrainRequired_.store(false, std::memory_order_release);
                Child_.store({}, std::memory_order_release);
            }

            auto RequireChildDrain() noexcept -> void
            {
                ChildDrainRequired_.store(true, std::memory_order_release);
            }

            auto Seal() noexcept -> void override
            {
                Parent_->Seal();
            }

            [[nodiscard]] auto Executor() const -> Net::any_io_executor override
            {
                return Parent_->Executor();
            }

            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            {
                if (!Parent_->IsRetired()) return false;
                if (!ChildDrainRequired_.load(std::memory_order_acquire)) return true;
                const auto Child = Child_.load(std::memory_order_acquire);
                return Child && Child->IsRetired();
            }

            [[nodiscard]] auto Drain()
                -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
            {
                return DrainOwned(shared_from_this());
            }

        private:
            [[nodiscard]] static auto DrainOwned(std::shared_ptr<ConnActivity> Owner)
                -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
            {
                co_await Net::this_coro::throw_if_cancelled(false);
                co_await Net::this_coro::reset_cancellation_state(
                    Net::disable_cancellation());
                auto Result = co_await Owner->Parent_->Drain();
                if (Owner->ChildDrainRequired_.load(std::memory_order_acquire))
                {
                    const auto Child = Owner->Child_.load(std::memory_order_acquire);
                    if (!Child)
                    {
                        if (Result)
                        {
                            Result = std::unexpected(
                                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                        }
                    }
                    else
                    {
                        const auto ChildResult = co_await Child->Drain();
                        if (!ChildResult && Result)
                        {
                            Result = std::unexpected(ChildResult.error());
                        }
                    }
                }
                co_return Result;
            }

            std::shared_ptr<Prism::Contract::CarrierActivity> Parent_;
            std::atomic<std::shared_ptr<Prism::Contract::CarrierActivity>> Child_{};
            std::atomic_bool ChildDrainRequired_{false};
        };
    }

    template <Prism::Memory::Restrict Memory>
    class Dgram;

    struct ConnOptions final
    {
        /**
         * @brief 固定连接执行域；连接保留 executor 值，但不拥有其 execution_context。
         * @note 上游进程或 worker owner 必须保持该 context，直到连接和活动均排空。
         */
        Net::any_io_executor Executor;
        std::array<std::uint8_t, 16> Uuid{};
        RandomSource Source{};
        Prism::SharedAuthenticator AuthenticatorOwner;
    };

    /**
     * @class Conn
     * @brief VMess 流连接装饰器。
     * @tparam Memory 会话内存策略
 * @details 该类不再拥有协议状态机实现，只负责固定顺序持有 session、I/O、
 *          chunk、handshake owner；executor 由真实上游入口在构造时提供。
     */
    template <Prism::Memory::Restrict Memory = Prism::Memory::SessionResource<>>
    class Conn : public Prism::Transmission
    {
    public:
        /** @brief 接管执行器、UUID、随机源和认证器配置。 */
        explicit Conn(ConnOptions Options)
            : Prism::Transmission(std::move(Options.Executor)),
              Session_(Options.Uuid, std::move(Options.Source), std::move(Options.AuthenticatorOwner)),
              Io_(Session_, Prism::Transmission::Executor()),
              Chunk_(Session_, Io_), Handshake_(Session_, Io_, Chunk_),
              Activity_(std::make_shared<detail::ConnActivity>(Prism::Transmission::Activity()))
        {
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Prism::Transmission::Executor();
        }

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        /** @brief 一次真实部分读；结果与借用沿正式前门交付一次，本连接 owner 全程保活。 */
        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ChunkReadWork>(ChunkRead{std::static_pointer_cast<Conn>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /** @brief 一次真实部分写；保持底层短写与 chunk 加密封装语义。 */
        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Initiate<ChunkWriteWork>(ChunkWrite{std::static_pointer_cast<Conn>(Transmission::shared_from_this()), Buffer}, std::move(Handler));
        }

        /** @brief 真实写半关闭转交底层载体；读取方向保持可用。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Io_.WriteShutdown(std::move(Handler));
        }

        /** @brief 封止并交付底层关闭；实际退出由 Activity()->Drain() 另行等待。 */
        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (Io_.Underlying()) Activity_->RequireChildDrain();
            return Io_.Close();
        }

        /** @brief 可重复取消底层 I/O；成功不表示连接已关闭。 */
        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            return Io_.Cancel();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission* override
        {
            return Io_.NextLayer();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Prism::Transmission* override
        {
            return Io_.NextLayer();
        }

        [[nodiscard]] auto Release() -> Prism::SharedTransmission override
        {
            auto Released = Io_.Release();
            if (Released) Activity_->ClearChild();
            return Released;
        }

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Io_.HasUpstream() && Session_.IsHandshaken();
        }

        [[nodiscard]] auto Underlying() noexcept -> Prism::SharedTransmission
        {
            return Io_.Underlying();
        }

        [[nodiscard]] auto Arena() noexcept -> Prism::Memory::ResourcePointer
        {
            return Session_.Arena();
        }

        /**
         * @brief 写入请求握手并在挂起期间固定连接 owner。
         * @param Upstream 所有权移交给连接。
         * @param Target 借用至握手完成。
         * @return VMess 协议错误；上游与本连接的关闭由调用方继续管理。
         */
        [[nodiscard]] auto WriteHandshake(
            Prism::SharedTransmission Upstream,
            const Address& Target,
            Command CommandValue = Command::Tcp)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            Activity_->AttachChild(Upstream ? Upstream->Activity() : nullptr);
            auto Owner = std::static_pointer_cast<Conn>(
                Prism::Transmission::weak_from_this().lock());
            return WriteHandshakeOwned(HandshakeWriteRequest{
                std::move(Owner), std::move(Upstream), &Target, CommandValue});
        }

        /**
         * @brief 读取请求握手并在挂起期间固定连接 owner。
         * @param Upstream 上游传输（所有权移交）。
         * @return 协议错误与解析出的请求。
         */
        [[nodiscard]] auto ReadHandshake(
            Prism::SharedTransmission Upstream,
            bool EnableUdp = true,
            bool EnableMux = true)
            -> Net::awaitable<std::expected<Message, Prism::Fault::Failure>>
        {
            Activity_->AttachChild(Upstream ? Upstream->Activity() : nullptr);
            auto Owner = std::static_pointer_cast<Conn>(
                Prism::Transmission::weak_from_this().lock());
            return ReadHandshakeOwned(HandshakeReadRequest{
                std::move(Owner), std::move(Upstream), EnableUdp, EnableMux});
        }

        [[nodiscard]] auto Parsed() const -> const Message&
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
        template <Prism::Memory::Restrict DgramMemory>
        friend class Dgram;

        using Session = detail::ConnSession<Memory>;
        using Io = detail::ConnIo<Memory>;
        using Chunk = detail::ConnChunk<Memory>;
        using Handshake = detail::ConnHandshake<Memory>;

        /** @brief 包连接专用的 VMess datagram wire owner；不作为 Conn public packet facade。 */
        [[nodiscard]] auto AsyncSendDatagram(
            std::span<const std::uint8_t> Payload)
            -> Net::awaitable<Prism::Contract::Io::PacketTransferResult>
        {
            auto Owner = std::static_pointer_cast<Conn>(
                Prism::Transmission::weak_from_this().lock());
            return SendDatagramOwned(std::move(Owner), Payload);
        }

        /** @brief 包连接专用的 VMess datagram wire owner；输出 buffer 借用至 completion。 */
        [[nodiscard]] auto AsyncReceiveDatagram(
            std::vector<std::uint8_t>& Payload)
            -> Net::awaitable<Prism::Contract::Io::PacketTransferResult>
        {
            auto Owner = std::static_pointer_cast<Conn>(
                Prism::Transmission::weak_from_this().lock());
            return ReceiveDatagramOwned(std::move(Owner), Payload);
        }

        struct HandshakeWriteRequest final
        {
            std::shared_ptr<Conn> Owner;
            Prism::SharedTransmission Upstream;
            const Address *Target;
            Command CommandValue;
        };
        struct HandshakeReadRequest final
        {
            std::shared_ptr<Conn> Owner;
            Prism::SharedTransmission Upstream;
            bool EnableUdp;
            bool EnableMux;
        };

        [[nodiscard]] static auto WriteHandshakeOwned(HandshakeWriteRequest Request)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            if (!Request.Owner)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            co_return co_await Request.Owner->Handshake_.WriteHandshake(
                std::move(Request.Upstream), *Request.Target,
                static_cast<std::uint8_t>(Request.CommandValue));
        }
        [[nodiscard]] static auto ReadHandshakeOwned(HandshakeReadRequest Request)
            -> Net::awaitable<std::expected<Message, Prism::Fault::Failure>>
        {
            if (!Request.Owner)
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            co_return co_await Request.Owner->Handshake_.ReadHandshake(
                std::move(Request.Upstream), Request.EnableUdp, Request.EnableMux);
        }
        [[nodiscard]] static auto SendDatagramOwned(
            std::shared_ptr<Conn> Owner, std::span<const std::uint8_t> Payload)
            -> Net::awaitable<Prism::Contract::Io::PacketTransferResult>
        {
            if (!Owner)
                co_return Prism::Contract::Io::PacketTransferResult{
                    0, 0, {Prism::Fault::Code::IoError}};
            co_return co_await Owner->Chunk_.AsyncSendDatagram(Payload);
        }
        [[nodiscard]] static auto ReceiveDatagramOwned(
            std::shared_ptr<Conn> Owner, std::vector<std::uint8_t> &Payload)
            -> Net::awaitable<Prism::Contract::Io::PacketTransferResult>
        {
            if (!Owner)
                co_return Prism::Contract::Io::PacketTransferResult{
                    0, 0, {Prism::Fault::Code::IoError}};
            co_return co_await Owner->Chunk_.AsyncReceiveDatagram(Payload);
        }

        struct ChunkRead final { std::shared_ptr<Conn> Owner; std::span<std::byte> Buffer; };
        struct ChunkWrite final { std::shared_ptr<Conn> Owner; std::span<const std::byte> Buffer; };
        struct ChunkReadWork final
        {
            template<class State>
            auto operator()(State Operation, ChunkRead Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                co_return std::tuple{co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->Chunk_.ReadSome(Input.Buffer), Net::deferred)};
            }
        };
        struct ChunkWriteWork final
        {
            template<class State>
            auto operator()(State Operation, ChunkWrite Input) const -> void
            {
                Prism::Transmission::ConfigureIo(Operation);
                if (!Input.Owner) co_return std::tuple{Prism::IoResult{0, {Prism::Fault::Code::InvalidArgument}}};
                co_return std::tuple{co_await Net::co_spawn(
                    Input.Owner->Executor(), Input.Owner->Chunk_.WriteSome(Input.Buffer), Net::deferred)};
            }
        };
        template<class Work, class Input>
        auto Initiate(Input Value, Completion Handler) -> void
        {
            Net::async_initiate<Completion, void(Prism::IoResult)>(
                Net::co_composed<void(Prism::IoResult)>(Work{}, Executor()), Handler, std::move(Value));
        }

        Session Session_;
        Io Io_;
        Chunk Chunk_;
        Handshake Handshake_;
        std::shared_ptr<detail::ConnActivity> Activity_;
    };

    /// 流连接共享指针。
    using SharedConn = std::shared_ptr<Conn<>>;

    static_assert(Prism::TransmissionLike<Conn<>>);

} // namespace Prism::Vmess
