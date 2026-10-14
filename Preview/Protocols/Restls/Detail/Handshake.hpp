/**
 * @file Server.hpp
 * @brief Restls 服务端中间人握手与首帧接管。
 * @details 转发客户端 TLS flight，提取并转发 ServerHello，认证首个加密记录，
 *          再把仍由客户端拥有的传输交给 Restls Conn。
 */
#pragma once

#include <Preview/Protocols/Restls/Detail/Record.hpp>
#include <Preview/Protocols/Restls/Detail/Session.hpp>
#include <Preview/Protocols/Restls/Detail/Control.hpp>
#include <Preview/Protocols/Restls/Types.hpp>
#include <Preview/Protocols/Restls/Detail/Io.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace Preview::Restls::Detail
{
    namespace Net = boost::asio;
    using Net::experimental::awaitable_operators::operator||;

    namespace HandshakeDetail
    {
        /** @brief 将传输层 drain 失败投影为 Restls 失败，不丢失其原生 cause。 */
        [[nodiscard]] inline auto RetirementFailure(
            const Preview::Fault::Failure &Value) noexcept -> Failure
        {
            const auto Native = Preview::Fault::ToNative(Value);
            return {MapWireError(Native), Native};
        }
    }

    /**
     * @brief 单个 Restls 服务端中间人请求 owner。
     * @details Run 期间接管入站传输；失败时 Cancel、Close 并等待整条 Activity 链退栈，
     *          清理失败的实物转交进程级 ClosingStorage，由原 executor reclaimer 重试。
     */
    class ServerSession final
    {
        struct State final
        {
            explicit State(Net::any_io_executor Executor) : Signal(std::move(Executor))
            {
                Signal.expires_at(std::chrono::steady_clock::time_point::max());
            }

            SharedTransmission Client;
            SharedTransmission Target;
            std::array<std::uint8_t, 32> Secret{};
            std::array<std::uint8_t, 32> ServerRandom{};
            std::vector<std::uint8_t> ClientFinished;
            std::vector<std::uint8_t> FirstEncrypted;
            Failure FirstFailure{};
            bool Stop{false};
            Net::steady_timer Signal;
        };

    public:
        /** @brief 构造本请求固定的拨号能力；无 socket 或协程在此启动。 */
        explicit ServerSession(ServerOptions Options) : Options_(std::move(Options)) {}
        ServerSession(const ServerSession &) = delete;
        auto operator=(const ServerSession &) -> ServerSession & = delete;

        /**
         * @brief 完成真实 TLS 中间人握手并接管 Restls 连接。
         * @param Inbound 按值移交的客户端传输；失败时本 owner 关闭并等待其真实退栈。
         * @param Config 同步借用的密码与 TLS 版本配置。
         * @return 成功时为唯一 Conn owner；失败时保留协议分类及底层原生 cause。
         */
        [[nodiscard]] auto Run(SharedTransmission Inbound, const ServerConfig &Config)
            -> Net::awaitable<Result<SharedConn>>
        {
            if (!Inbound)
                co_return std::unexpected(ProtocolFailure(Preview::Error::NotOpen));
            if (!Options_.DialTarget || Config.password.empty())
                co_return co_await RejectInput(
                    std::move(Inbound), ProtocolFailure(Preview::Error::Unsupported));

            auto ClientHello = co_await ReadRecordWire(Inbound);
            if (!ClientHello)
                co_return co_await RejectInput(std::move(Inbound), ClientHello.error());
            if (ClientHello->empty() || ClientHello->front() != 0x16)
                co_return co_await RejectInput(
                    std::move(Inbound), ProtocolFailure(Preview::Error::BadMessage));

            auto Dialed = co_await DialTarget(*ClientHello);
            if (!Dialed)
                co_return co_await RejectInput(std::move(Inbound), Dialed.error());

            auto Session = std::make_shared<State>(Inbound->Executor());
            Session->Client = std::move(Inbound);
            Session->Target = std::move(*Dialed);
            Session->Secret = DeriveSecret(Config.password);

            auto Forward = co_await SendAllWire(
                Session->Target, std::span<const std::uint8_t>(*ClientHello));
            if (!Forward)
                co_return co_await RejectSession(Session, Forward.error());

            auto ServerHello = co_await ReadRecordWire(Session->Target);
            if (!ServerHello)
                co_return co_await RejectSession(Session, ServerHello.error());
            const auto Random = ParseServerHelloRandom(*ServerHello);
            if (!Random)
                co_return co_await RejectSession(
                    Session, ProtocolFailure(Preview::Error::BadMessage));
            Session->ServerRandom = *Random;

            Forward = co_await SendAllWire(
                Session->Client, std::span<const std::uint8_t>(*ServerHello));
            if (!Forward)
                co_return co_await RejectSession(Session, Forward.error());

            const auto LoopResult = co_await (ClientLoop(Session) || BackendLoop(Session));
            if (Session->FirstFailure.Failed())
                co_return co_await RejectSession(Session, Session->FirstFailure);
            if (Session->ClientFinished.empty() || Session->FirstEncrypted.empty())
            {
                const auto LoopFailure = std::visit(
                    [](const auto &Value) { return Value; }, LoopResult);
                const auto Failure = LoopFailure.Failed()
                                         ? LoopFailure
                                         : ProtocolFailure(Preview::Error::BadAuth);
                co_return co_await RejectSession(Session, Failure);
            }

            auto Connection = std::make_shared<Conn<>>(
                std::move(Session->Client), Config.password);
            auto Initialized = co_await Connection->ReadHandshake(
                Session->ServerRandom, Session->ClientFinished);
            const auto TargetRetirement = co_await TransportRetirement::RetireAndDrain(
                std::move(Session->Target));
            if (!Initialized)
            {
                const auto ConnectionRetirement = co_await RetireConnection(std::move(Connection));
                auto CleanupFailure = TargetRetirement
                                          ? Failure{}
                                          : HandshakeDetail::RetirementFailure(TargetRetirement.error());
                if (!ConnectionRetirement)
                {
                    CleanupFailure = PreserveFirstFailure(
                        CleanupFailure,
                        HandshakeDetail::RetirementFailure(ConnectionRetirement.error()));
                }
                co_return std::unexpected(
                    PreserveFirstFailure(Initialized.error(), CleanupFailure));
            }
            if (!TargetRetirement)
            {
                const auto ConnectionRetirement = co_await RetireConnection(std::move(Connection));
                const auto TargetFailure = HandshakeDetail::RetirementFailure(TargetRetirement.error());
                const auto CleanupFailure = ConnectionRetirement
                                                ? Failure{}
                                                : HandshakeDetail::RetirementFailure(
                                                      ConnectionRetirement.error());
                co_return std::unexpected(
                    PreserveFirstFailure(TargetFailure, CleanupFailure));
            }
            if (Config.Tls13) Connection->AllowTls13EncryptedCloseNotify();
            co_return Connection;
        }

    private:
        /** @brief 以原生传输错误构造一次 Restls I/O 失败。 */
        [[nodiscard]] auto DialTarget(const std::vector<std::uint8_t> &ClientHello)
            -> Net::awaitable<Result<SharedTransmission>>
        {
            try
            {
                auto Dialed = co_await Options_.DialTarget(
                    std::span<const std::uint8_t>(ClientHello));
                if (!Dialed)
                    co_return std::unexpected(HandshakeDetail::RetirementFailure(Dialed.error()));
                if (!*Dialed)
                    co_return std::unexpected(ProtocolFailure(Preview::Error::NotOpen));
                co_return std::move(*Dialed);
            }
            catch (const boost::system::system_error &Exception)
            {
                co_return std::unexpected(WireFailure(
                    Preview::Fault::FromNative(
                        static_cast<std::error_code>(Exception.code()))));
            }
            catch (const std::system_error &Exception)
            {
                co_return std::unexpected(WireFailure(
                    Preview::Fault::FromNative(Exception.code())));
            }
            catch (...)
            {
                co_return std::unexpected(ProtocolFailure(Preview::Error::IoError));
            }
        }

        /** @brief 先完成入站真实 retirement，再返回首个握手或 I/O cause。 */
        [[nodiscard]] static auto RejectInput(SharedTransmission Inbound, Failure Primary)
            -> Net::awaitable<Result<SharedConn>>
        {
            const auto Retired = co_await TransportRetirement::RetireAndDrain(std::move(Inbound));
            if (!Retired)
                Primary = PreserveFirstFailure(
                    Primary, HandshakeDetail::RetirementFailure(Retired.error()));
            co_return std::unexpected(Primary);
        }

        /** @brief 封止两端新操作、发送控制命令并等待两条 Activity 链退栈。 */
        [[nodiscard]] static auto RejectSession(
            const std::shared_ptr<State> &Session,
            Failure Primary) -> Net::awaitable<Result<SharedConn>>
        {
            Session->Stop = true;
            Session->Signal.cancel();
            const auto Target = co_await TransportRetirement::RetireAndDrain(
                std::move(Session->Target));
            const auto Client = co_await TransportRetirement::RetireAndDrain(
                std::move(Session->Client));
            if (!Target)
                Primary = PreserveFirstFailure(
                    Primary, HandshakeDetail::RetirementFailure(Target.error()));
            if (!Client)
                Primary = PreserveFirstFailure(
                    Primary, HandshakeDetail::RetirementFailure(Client.error()));
            co_return std::unexpected(Primary);
        }

        /** @brief 初始化失败时关闭 Conn 并等待包装层和其真实底层退栈。 */
        [[nodiscard]] static auto RetireConnection(SharedConn Connection)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_return co_await TransportRetirement::RetireAndDrain(std::move(Connection));
        }

        /** @brief 首次错误只写入一次；后续取消不覆盖真实请求 cause。 */
        static auto RecordFailure(const std::shared_ptr<State> &Session, Failure Value) -> void
        {
            if (Session->FirstFailure.Succeeded() && Value.Failed())
                Session->FirstFailure = Value;
        }

        /** @brief 结束并行循环并唤醒客户端首帧等待者。 */
        static auto RequestStop(const std::shared_ptr<State> &Session) -> void
        {
            Session->Stop = true;
            Session->Signal.cancel();
        }

        /** @brief 检查 TLS 记录是否为 application_data。 */
        [[nodiscard]] static auto IsApplicationData(
            const std::vector<std::uint8_t> &Record) noexcept -> bool
        {
            return Record.size() >= TlsHdrlen && Record.front() == TlsApplicationData;
        }

        /** @brief 将客户端握手记录转发到后端并接管首个 ClientFinished。 */
        [[nodiscard]] auto ClientLoop(const std::shared_ptr<State> &Session)
            -> Net::awaitable<Failure>
        {
            while (!Session->Stop)
            {
                auto Record = co_await ReadRecordWire(Session->Client);
                if (!Record)
                {
                    if (!Session->Stop)
                    {
                        RecordFailure(Session, Record.error());
                        RequestStop(Session);
                    }
                    co_return Record.error();
                }
                if (IsApplicationData(*Record) && Session->ClientFinished.empty())
                {
                    Session->ClientFinished = std::move(*Record);
                    const auto Forward = co_await SendAllWire(
                        Session->Target,
                        std::span<const std::uint8_t>(Session->ClientFinished));
                    if (!Forward) RecordFailure(Session, Forward.error());
                    if (Session->FirstEncrypted.empty() && !Session->FirstFailure.Failed())
                    {
                        boost::system::error_code WaitError;
                        co_await Session->Signal.async_wait(
                            Net::redirect_error(Net::use_awaitable, WaitError));
                    }
                    RequestStop(Session);
                    co_return Session->FirstFailure;
                }
                const auto Forward = co_await SendAllWire(
                    Session->Target, std::span<const std::uint8_t>(*Record));
                if (!Forward)
                {
                    RecordFailure(Session, Forward.error());
                    RequestStop(Session);
                    co_return Forward.error();
                }
            }
            co_return Failure{};
        }

        /** @brief 转发后端记录并保护首个服务端 application_data。 */
        [[nodiscard]] auto BackendLoop(const std::shared_ptr<State> &Session)
            -> Net::awaitable<Failure>
        {
            while (!Session->Stop)
            {
                auto Record = co_await ReadRecordWire(Session->Target);
                if (!Record)
                {
                    if (!Session->Stop)
                    {
                        RecordFailure(Session, Record.error());
                        RequestStop(Session);
                    }
                    co_return Record.error();
                }
                if (IsApplicationData(*Record) && Session->FirstEncrypted.empty())
                {
                    Session->FirstEncrypted = *Record;
                    const auto Protected = ProtectFirstEncrypted(
                        *Record, std::span<const std::uint8_t, 32>(Session->Secret),
                        std::span<const std::uint8_t, 32>(Session->ServerRandom));
                    if (Protected.first != Preview::Error::None)
                    {
                        const auto Failure = ProtocolFailure(Protected.first);
                        RecordFailure(Session, Failure);
                        RequestStop(Session);
                        co_return Failure;
                    }
                    const auto Forward = co_await SendAllWire(
                        Session->Client, std::span<const std::uint8_t>(Protected.second));
                    if (!Forward)
                    {
                        RecordFailure(Session, Forward.error());
                        RequestStop(Session);
                        co_return Forward.error();
                    }
                    Session->Signal.cancel();
                    if (!Session->ClientFinished.empty()) RequestStop(Session);
                    continue;
                }
                const auto Forward = co_await SendAllWire(
                    Session->Client, std::span<const std::uint8_t>(*Record));
                if (!Forward)
                {
                    if (!Session->Stop)
                    {
                        RecordFailure(Session, Forward.error());
                        RequestStop(Session);
                    }
                    co_return Forward.error();
                }
            }
            co_return Failure{};
        }

        ServerOptions Options_;
    };
}
