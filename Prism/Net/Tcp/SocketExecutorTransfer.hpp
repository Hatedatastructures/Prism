/**
 * @file SocketExecutorTransfer.hpp
 * @brief 在无在途 I/O 时把已接纳 TCP socket 的 native owner 移交到目标 executor。
 */
#pragma once

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <cerrno>
#include <unistd.h>
#endif

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/system_error.hpp>

#include <expected>
#include <system_error>
#include <utility>

namespace Prism::Network::Tcp
{
    namespace Net = boost::asio;
    using TcpSocket = Net::ip::tcp::socket;

    namespace Detail
    {
        /** @brief native socket 唯一所有者；构造不分配，离开作用域前关闭或显式释放。 */
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

            /** @brief assign 成功后解除本 guard 所有权；返回句柄只作交接记录。 */
            [[nodiscard]] auto Release() noexcept -> TcpSocket::native_handle_type
            {
                Owns_ = false;
                return Handle_;
            }

            /** @brief 用平台 socket API 关闭；一次性处理以避免 POSIX EINTR 后重试误关复用 fd。 */
            [[nodiscard]] auto Close() noexcept -> std::error_code
            {
                if (!Owns_)
                {
                    return {};
                }
                Owns_ = false;
#if defined(_WIN32)
                if (::closesocket(Handle_) == SOCKET_ERROR)
                {
                    return static_cast<std::error_code>(boost::system::error_code(
                        ::WSAGetLastError(), Net::error::get_system_category()));
                }
#else
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

        /** @brief 转移失败时先关闭 native owner；关闭失败作为最终原生失败返回。 */
        [[nodiscard]] inline auto CloseAndPreserveFailure(
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
    } // 内部句柄所有者

    /**
     * @brief 把已接纳 TCP socket 转交给目标 executor，并返回唯一 owning socket。
     * @details 输入：Socket 按值移交；Executor 是目标 socket executor。调用前必须确保
     *          socket 没有任何在途 I/O、控制交付或其他并发访问。输出：成功值是唯一 socket
     *          owner；调用者可将它移入 Reliable，之后最终关闭归该传输 owner。失败时 native
     *          handle 由无分配 guard 用平台 API 关闭，不回退到源 executor。目标 executor 的
     *          execution context 必须保持存活到 socket 的 I/O、取消、关闭和真实 drain 结束。
     *          Release/assign/系统异常以 Fault::Failure 保留原生 category/value；无法映射的
     *          异常返回 ResourceUnavailable。此函数不执行半关闭，不保留 socket 别名。
     */
    [[nodiscard]] inline auto MoveAcceptedSocket(
        TcpSocket Socket, Net::any_io_executor Executor)
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
            // Asio 保留源 socket 的 native owner；参数析构会按源 executor 关闭它。
            return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(ReleaseError)));
        }

        // Release 成功后第一时间建立无分配 owner，覆盖之后的构造、assign 和异常路径。
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
} // TCP 所有权移交