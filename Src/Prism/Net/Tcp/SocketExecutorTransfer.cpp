/** @file SocketExecutorTransfer.cpp @brief 已接纳 socket 的跨 executor native owner 移交。 */
#include <Prism/Net/Tcp/SocketExecutorTransfer.hpp>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <cerrno>
#include <unistd.h>
#endif

#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <expected>
#include <system_error>
#include <utility>

namespace Prism::Network::Tcp
{
    namespace Detail
    {
        class NativeSocketGuard final
        {
        public:
            explicit NativeSocketGuard(const TcpSocket::native_handle_type Handle) noexcept
                : Handle_(Handle)
            {
            }

            NativeSocketGuard(const NativeSocketGuard&) = delete;
            auto operator=(const NativeSocketGuard&) -> NativeSocketGuard& = delete;

            ~NativeSocketGuard() noexcept
            {
                (void)Close();
            }

            [[nodiscard]] auto Get() const noexcept -> TcpSocket::native_handle_type
            {
                return Handle_;
            }

            [[nodiscard]] auto Release() noexcept -> TcpSocket::native_handle_type
            {
                Owns_ = false;
                return Handle_;
            }

            [[nodiscard]] auto Close() noexcept -> std::error_code
            {
                if (!Owns_)
                {
                    return {};
                }
#if defined(_WIN32)
                if (::closesocket(Handle_) == SOCKET_ERROR)
                {
                    const auto CloseError = ::WSAGetLastError();
                    if (CloseError == WSAEWOULDBLOCK)
                    {
                        const linger AbortiveClose{1, 0};
                        // WSAEWOULDBLOCK 保留有效句柄；优先改为中止关闭，并始终重试 closesocket。
                        (void)::setsockopt(Handle_, SOL_SOCKET, SO_LINGER,
                            reinterpret_cast<const char*>(&AbortiveClose),
                            static_cast<int>(sizeof(AbortiveClose)));
                        if (::closesocket(Handle_) == SOCKET_ERROR)
                        {
                            const auto RetryError = ::WSAGetLastError();
                            if (RetryError != WSAEWOULDBLOCK) Owns_ = false;
                            return static_cast<std::error_code>(boost::system::error_code(
                                RetryError, Net::error::get_system_category()));
                        }
                        Owns_ = false;
                        return {};
                    }
                    Owns_ = false;
                    return static_cast<std::error_code>(boost::system::error_code(
                        CloseError, Net::error::get_system_category()));
                }
                Owns_ = false;
#else
                Owns_ = false;
                if (::close(Handle_) != 0)
                {
                    return {errno, std::generic_category()};
                }
#endif
                return {};
            }

        private:
            TcpSocket::native_handle_type Handle_;
            bool Owns_{true};
        };

        [[nodiscard]] auto CloseAndPreserveFailure(
            NativeSocketGuard& Guard, Prism::Fault::Failure Failure) noexcept
            -> Prism::Fault::Failure
        {
            const auto CloseFailure = Guard.Close();
            if (CloseFailure)
            {
                return Prism::Fault::FromNative(CloseFailure);
            }
            return Failure;
        }
    }

    auto MoveAcceptedSocket(TcpSocket Socket, Net::any_io_executor Executor)
        -> std::expected<TcpSocket, Prism::Fault::Failure>
    {
        if (!Socket.is_open())
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }

        boost::system::error_code EndpointError;
        const auto Protocol = Socket.local_endpoint(EndpointError).protocol();
        if (EndpointError)
        {
            return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(EndpointError)));
        }

        boost::system::error_code ReleaseError;
        const auto Native = Socket.release(ReleaseError);
        if (ReleaseError)
        {
            return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(ReleaseError)));
        }

        Detail::NativeSocketGuard NativeOwner(Native);
        try
        {
            TcpSocket Target(std::move(Executor));
            boost::system::error_code AssignError;
            Target.assign(Protocol, NativeOwner.Get(), AssignError);
            if (AssignError)
            {
                return std::unexpected(Detail::CloseAndPreserveFailure(
                    NativeOwner, Prism::Fault::FromNative(
                        static_cast<std::error_code>(AssignError))));
            }
            (void)NativeOwner.Release();
            return std::expected<TcpSocket, Prism::Fault::Failure>{std::move(Target)};
        }
        catch (const boost::system::system_error& Error)
        {
            return std::unexpected(Detail::CloseAndPreserveFailure(
                NativeOwner, Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code()))));
        }
        catch (const std::system_error& Error)
        {
            return std::unexpected(Detail::CloseAndPreserveFailure(
                NativeOwner, Prism::Fault::FromNative(Error.code())));
        }
        catch (...)
        {
            return std::unexpected(Detail::CloseAndPreserveFailure(
                NativeOwner, Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable}));
        }
    }
}
