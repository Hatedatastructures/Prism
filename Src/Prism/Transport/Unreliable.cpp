/** @file Unreliable.cpp @brief UDP 套接字配置、对端过滤与类型化数据报收发实现。 */
#include <Prism/Transport/Unreliable.hpp>
#include <Prism/Transport/Io/Completion.hpp>

#include <boost/asio/async_result.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <charconv>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <utility>

namespace Prism::Transport
{
    namespace
    {
        struct ParsedUnreliableRemote final
        {
            std::string Host;
            unsigned short Port{0};
            std::optional<Net::ip::address> Address;
        };

        [[nodiscard]] auto ParsePort(const std::string_view Text)
            -> std::optional<unsigned short>
        {
            if (Text.empty())
            {
                return std::nullopt;
            }
            unsigned long Value = 0;
            const auto Parsed = std::from_chars(Text.data(), Text.data() + Text.size(), Value, 10);
            if (Parsed.ec != std::errc{} || Parsed.ptr != Text.data() + Text.size() ||
                Value > 65535UL)
            {
                return std::nullopt;
            }
            return static_cast<unsigned short>(Value);
        }

        [[nodiscard]] auto IsValidDomain(const std::string_view Host) noexcept -> bool
        {
            if (Host.empty() || Host.front() == '.' || Host.front() == '-' ||
                Host.find_first_of("[]:/\\ \t\r\n") != std::string_view::npos)
            {
                return false;
            }
            bool LabelStart = true;
            char Previous = 0;
            for (const auto Character : Host)
            {
                if (Character == '.')
                {
                    if (LabelStart || Previous == '-')
                    {
                        return false;
                    }
                    LabelStart = true;
                    Previous = Character;
                    continue;
                }
                if (Character == '-' && LabelStart)
                {
                    return false;
                }
                if (!std::isalnum(static_cast<unsigned char>(Character)) && Character != '-')
                {
                    return false;
                }
                LabelStart = false;
                Previous = Character;
            }
            return !LabelStart && Previous != '-';
        }

        [[nodiscard]] auto ParseRemote(const std::string_view Remote)
            -> std::optional<ParsedUnreliableRemote>
        {
            if (Remote.empty())
            {
                return std::nullopt;
            }

            std::string_view Host;
            std::string_view PortText;
            std::optional<Net::ip::address> Address;
            if (Remote.front() == '[')
            {
                const auto Close = Remote.find(']');
                if (Close == std::string_view::npos || Close == 1 ||
                    Close + 1 >= Remote.size() || Remote[Close + 1] != ':')
                {
                    return std::nullopt;
                }
                Host = Remote.substr(1, Close - 1);
                PortText = Remote.substr(Close + 2);
                boost::system::error_code ErrorCode;
                const auto ParsedAddress = Net::ip::make_address_v6(Host, ErrorCode);
                if (ErrorCode)
                {
                    return std::nullopt;
                }
                Address = ParsedAddress;
            }
            else
            {
                const auto FirstColon = Remote.find(':');
                const auto LastColon = Remote.rfind(':');
                if (FirstColon == std::string_view::npos || FirstColon != LastColon)
                {
                    return std::nullopt;
                }
                Host = Remote.substr(0, FirstColon);
                PortText = Remote.substr(FirstColon + 1);
                if (Host.empty() || Host.find_first_of("[]") != std::string_view::npos)
                {
                    return std::nullopt;
                }
                boost::system::error_code ErrorCode;
                const auto ParsedAddress = Net::ip::make_address(Host, ErrorCode);
                if (!ErrorCode)
                {
                    Address = ParsedAddress;
                }
                else if (!IsValidDomain(Host))
                {
                    return std::nullopt;
                }
            }

            const auto Port = ParsePort(PortText);
            if (!Port)
            {
                return std::nullopt;
            }
            return ParsedUnreliableRemote{std::string(Host), *Port, Address};
        }
    }

    struct Unreliable::ResolveOperation final
    {
        template<class State>
        auto operator()(State Operation, std::shared_ptr<Unreliable> Owner) const -> void
        {
            Prism::Transmission::ConfigureIo(Operation);
            if (Owner->Remote_ || Owner->Host_.empty()) co_return std::tuple{boost::system::error_code{}};
            Net::ip::udp::resolver Resolver(Owner->Executor());
            auto [Error, Entries] = co_await Resolver.async_resolve(
                Owner->Host_, std::to_string(Owner->Port_), Net::as_tuple(Net::deferred));
            if (Error) co_return std::tuple{Error};
            for (const auto& Entry : Entries)
            {
                Owner->Socket_.open(Entry.endpoint().protocol(), Error);
                if (Error) continue;
                Owner->Remote_ = Entry.endpoint(); Owner->Host_.clear(); Owner->Port_ = 0;
                co_return std::tuple{boost::system::error_code{}};
            }
            if (!Error) Error = Net::error::host_not_found;
            co_return std::tuple{Error};
        }
    };

    template<class Token>
    auto Unreliable::Resolve(Token&& Handler)
    {
        return Net::async_initiate<Token, void(boost::system::error_code)>(
            Net::co_composed<void(boost::system::error_code)>(ResolveOperation{}, Executor()), Handler, Self());
    }

    struct Unreliable::ReadOperation final
    {
        template<class State>
        auto operator()(State Operation, ReadInput Input) const -> void
        {
            Prism::Transmission::ConfigureIo(Operation);
            auto [Error] = co_await Input.Owner->Resolve(Net::as_tuple(Net::deferred));
            if (Error) co_return std::tuple{IoResult{0, Fault::FromNative(static_cast<std::error_code>(Error))}};
            while (true)
            {
                auto [ReceiveError, Bytes] = co_await Input.Owner->Socket_.async_receive_from(
                    Net::buffer(Input.Buffer.data(), Input.Buffer.size()), *Input.Sender, Net::as_tuple(Net::deferred));
                if (ReceiveError) co_return std::tuple{IoResult{Bytes, Fault::FromNative(static_cast<std::error_code>(ReceiveError))}};
                if (Input.Owner->Filter_ && (!Input.Owner->Remote_ || *Input.Sender != *Input.Owner->Remote_)) continue;
                if (Input.Owner->Capture_) { Input.Owner->Remote_ = *Input.Sender; Input.Owner->Filter_ = true; Input.Owner->Capture_ = false; }
                co_return std::tuple{IoResult{Bytes, {}}};
            }
        }
    };

    struct Unreliable::WriteOperation final
    {
        template<class State>
        auto operator()(State Operation, WriteInput Input) const -> void
        {
            Prism::Transmission::ConfigureIo(Operation);
            if (Input.Owner->WriteClosed_) co_return std::tuple{IoResult{0, {Fault::Code::ConnectionAborted}}};
            if (!Input.Target)
            {
                auto [Error] = co_await Input.Owner->Resolve(Net::as_tuple(Net::deferred));
                if (Error) co_return std::tuple{IoResult{0, Fault::FromNative(static_cast<std::error_code>(Error))}};
                Input.Target = Input.Owner->Remote_;
            }
            if (!Input.Target) co_return std::tuple{IoResult{0, {Fault::Code::InvalidArgument}}};
            auto [Error, Bytes] = co_await Input.Owner->Socket_.async_send_to(
                Net::buffer(Input.Buffer.data(), Input.Buffer.size()), *Input.Target, Net::as_tuple(Net::deferred));
            co_return std::tuple{IoResult{Bytes, Fault::FromNative(static_cast<std::error_code>(Error))}};
        }
    };

    class Unreliable::TimedCompletion final : public Detail::AssociatedCompletion<Completion>
    {
    public:
        TimedCompletion(std::shared_ptr<Net::steady_timer> Timer, Completion Handler)
            : AssociatedCompletion(std::move(Handler)), Timer_(std::move(Timer)) {}
        auto operator()(std::array<std::size_t, 2> Order, IoResult Result, boost::system::error_code TimerError) -> void
        {
            if (Order[0] == 1 && !TimerError) Result.Failure.Code = Fault::Code::Timeout;
            std::move(Handler_)(Result);
        }
    private:
        std::shared_ptr<Net::steady_timer> Timer_;
    };

    template<class Input>
    auto Unreliable::AwaitDatagram(Input Request, ExecutorType Executor) -> Net::awaitable<IoResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        const auto Cancellation = co_await Net::this_coro::cancellation_state;
        if (!!Cancellation.cancelled()) co_return IoResult{0, {Fault::Code::Canceled}};
        auto Token = Net::use_awaitable;
        co_return co_await Net::async_initiate<decltype(Token), void(IoResult)>(
            Initiation<Input>{std::move(Request), std::move(Executor)}, Token);
    }

    Unreliable::Unreliable(ExecutorType Executor, std::optional<EndpointType> Remote)
        : Transmission(Executor), Socket_(Executor), Remote_(std::move(Remote)),
          Filter_(Remote_.has_value()), Capture_(!Remote_)
    {
    }

    Unreliable::Unreliable(SocketType Socket, std::optional<EndpointType> Remote)
        : Transmission(Socket.get_executor()), Socket_(std::move(Socket)), Remote_(std::move(Remote)),
          Filter_(Remote_.has_value()), Capture_(!Remote_)
    {
    }

    auto Unreliable::Connect(const std::string& Text) -> ControlResult
    {
        const auto Target = ParseRemote(Text);
        if (!Target) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        boost::system::error_code Error;
        if (Socket_.is_open())
        {
            Socket_.close(Error);
            if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
        }
        Remote_.reset(); Host_.clear(); Port_ = 0; Filter_ = true; Capture_ = false;
        if (Target->Address)
        {
            EndpointType Endpoint(*Target->Address, Target->Port);
            Socket_.open(Endpoint.protocol(), Error);
            if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
            Remote_ = Endpoint;
        }
        else { Host_ = Target->Host; Port_ = Target->Port; }
        return {};
    }

    auto Unreliable::Bind(unsigned short Port) -> ControlResult
    {
        boost::system::error_code Error;
        if (!Socket_.is_open()) Socket_.open(Net::ip::udp::v4(), Error);
        if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
        Socket_.bind(EndpointType(Net::ip::udp::v4(), Port), Error);
        if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
        Remote_.reset(); Host_.clear(); Port_ = 0; Filter_ = false; Capture_ = true;
        return {};
    }

    auto Unreliable::SetRemote(const EndpointType& Endpoint) -> void
    {
        Remote_ = Endpoint; Host_.clear(); Port_ = 0; Filter_ = true; Capture_ = false;
    }

    auto Unreliable::AllowAnyPeer() noexcept -> void
    {
        Remote_.reset(); Host_.clear(); Port_ = 0; Filter_ = false; Capture_ = false;
    }

    auto Unreliable::LocalEndpoint() const -> EndpointType
    {
        boost::system::error_code Error;
        auto Value = Socket_.local_endpoint(Error);
        if (Error) return {};
        return Value;
    }

    auto Unreliable::Self() -> std::shared_ptr<Unreliable>
    {
        return std::static_pointer_cast<Unreliable>(weak_from_this().lock());
    }

    auto Unreliable::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        StartReceive(ReadInput{Self(), Buffer, &Sender_}, std::move(Handler));
    }

    auto Unreliable::StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        StartSend(WriteInput{Self(), Buffer, {}}, std::move(Handler));
    }

    auto Unreliable::StartWriteShutdown(Completion Handler) -> void
    {
        WriteClosed_ = true;
        Prism::Transmission::PostResult(Executor(), std::move(Handler), {});
    }

    auto Unreliable::OnClose() -> ControlResult
    {
        boost::system::error_code Error;
        Socket_.close(Error);
        if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
        return {};
    }

    auto Unreliable::OnCancel() -> ControlResult
    {
        boost::system::error_code Error;
        if (Socket_.is_open()) Socket_.cancel(Error);
        if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
        return {};
    }

    auto Unreliable::StartReceive(ReadInput Input, Completion Handler) -> void
    {
        Completion Routed(Detail::OriginalCompletion(Executor(), std::move(Handler)));
        if (Timeout_.count() <= 0)
        { Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(ReadOperation{}, Executor()), Routed, std::move(Input)); return; }
        /** @brief timer实体寿命独立于用户erased handler；异步等待自身仍保留关联属性。 */
        auto Timer = std::make_shared<Net::steady_timer>(Executor());
        Timer->expires_after(Timeout_);
        auto Token = Net::deferred;
        auto Read = Net::async_initiate<Net::deferred_t, void(IoResult)>(
            Net::co_composed<void(IoResult)>(ReadOperation{}, Executor()), Token, std::move(Input));
        Net::experimental::make_parallel_group(std::move(Read), Timer->async_wait(Net::deferred))
            .async_wait(Net::experimental::wait_for_one(), TimedCompletion(std::move(Timer), std::move(Routed)));
    }

    auto Unreliable::StartSend(WriteInput Input, Completion Handler) -> void
    {
        Completion Routed(Detail::OriginalCompletion(Executor(), std::move(Handler)));
        Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(WriteOperation{}, Executor()), Routed, std::move(Input));
    }

    auto Unreliable::ReceiveFrom(std::span<std::byte> Buffer, EndpointType& Sender) -> Net::awaitable<IoResult>
    {
        return AwaitDatagram(ReadInput{Self(), Buffer, &Sender}, Executor());
    }

    auto Unreliable::SendTo(std::span<const std::byte> Buffer, EndpointType Target) -> Net::awaitable<IoResult>
    {
        return AwaitDatagram(WriteInput{Self(), Buffer, std::move(Target)}, Executor());
    }

    auto MakeUnreliable(const Net::any_io_executor& Executor, std::optional<Net::ip::udp::endpoint> Remote)
        -> SharedTransmission
    {
        return std::make_shared<Unreliable>(Executor, std::move(Remote));
    }

    auto MakeUnreliable(Net::ip::udp::socket Socket, std::optional<Net::ip::udp::endpoint> Remote)
        -> SharedTransmission
    {
        return std::make_shared<Unreliable>(std::move(Socket), std::move(Remote));
    }
}
