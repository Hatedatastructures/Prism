/**
 * @file HttpForwardOriginFixture.hpp
 * @brief HTTP 环回源站 inline 生命周期 fixture。
 */
#pragma once
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <utility>

#include "HttpForwardApplicationFixture.hpp"
namespace Prism::Testing::HttpForward
{

    inline LoopbackOrigin::LoopbackOrigin()
        : WorkGuard_(Net::make_work_guard(Io_)), Acceptor_(Io_, Tcp::endpoint(Tcp::v4(), 0)), HoldTimer_(Io_)
    {
    }

    inline LoopbackOrigin::~LoopbackOrigin()
    {
        Stop();
    }

    inline auto LoopbackOrigin::Start(std::string Expected, std::string Response,
        const OriginCloseMode CloseMode) -> void
    {
        Expected_ = std::move(Expected);
        Response_ = std::move(Response);
        CloseMode_ = CloseMode;
        Net::co_spawn(Io_, Serve(), Net::detached);
        Thread_ = std::thread([this] { Io_.run(); });
    }

    inline auto LoopbackOrigin::ExpectAfterResponse(std::string Expected) -> void
    {
        PostResponseExpected_ = std::move(Expected);
    }

    inline auto LoopbackOrigin::Stop() -> void
    {
        if (!Thread_.joinable())
        {
            return;
        }

        /** @brief 借用存活到 join 的源站，在其 executor 上关闭监听和已接受连接。 */
        struct CloseOrigin final
        {
            LoopbackOrigin &Owner;

            auto operator()() noexcept -> void
            {
                boost::system::error_code Error;
                Owner.Acceptor_.close(Error);
                try
                {
                    (void)Owner.HoldTimer_.cancel();
                }
                catch (...)
                {
                    Owner.Io_.stop();
                }
                std::shared_ptr<Tcp::socket> Socket;
                {
                    std::lock_guard Lock(Owner.Mutex_);
                    Socket = Owner.Socket_;
                }
                if (Socket)
                {
                    Socket->close(Error);
                }
                Owner.WorkGuard_.reset();
            }
        };
        try
        {
            Net::post(Io_, CloseOrigin{*this});
        }
        catch (...)
        {
            Io_.stop();
        }
        Thread_.join();
    }

    inline auto LoopbackOrigin::Port() const -> std::uint16_t
    {
        return Acceptor_.local_endpoint().port();
    }

    inline auto LoopbackOrigin::WaitForAccepted(const std::chrono::milliseconds Timeout) -> bool
    {
        std::unique_lock Lock(Mutex_);
        if (!Condition_.wait_for(Lock, Timeout, [this] { return Accepted_ || Completed_; }))
        {
            return false;
        }
        return Accepted_;
    }

    inline auto LoopbackOrigin::WaitForResponse(const std::chrono::milliseconds Timeout) -> bool
    {
        std::unique_lock Lock(Mutex_);
        if (!Condition_.wait_for(Lock, Timeout, [this] { return ResponseSent_ || Completed_; }))
        {
            return false;
        }
        return ResponseSent_;
    }

    inline auto LoopbackOrigin::WaitForComplete(const std::chrono::milliseconds Timeout) -> bool
    {
        std::unique_lock Lock(Mutex_);
        return Condition_.wait_for(Lock, Timeout, [this] { return Completed_; });
    }

    inline auto LoopbackOrigin::Captured() const -> std::string
    {
        std::lock_guard Lock(Mutex_);
        return Captured_;
    }

    inline auto LoopbackOrigin::Extra() const -> std::string
    {
        std::lock_guard Lock(Mutex_);
        return Extra_;
    }

    inline auto LoopbackOrigin::PostResponseCaptured() const -> std::string
    {
        std::lock_guard Lock(Mutex_);
        return PostResponseCaptured_;
    }

    inline auto LoopbackOrigin::Serve() -> Net::awaitable<void>
    {
        auto Socket = std::make_shared<Tcp::socket>(co_await Net::this_coro::executor);
        {
            std::lock_guard Lock(Mutex_);
            Socket_ = Socket;
        }

        boost::system::error_code Error;
        co_await Acceptor_.async_accept(*Socket, Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            Complete();
            co_return;
        }
        {
            std::lock_guard Lock(Mutex_);
            Accepted_ = true;
        }
        Condition_.notify_all();

        std::string Captured(Expected_.size(), '\0');
        if (!Expected_.empty())
        {
            co_await Net::async_read(*Socket, Net::buffer(Captured),
                Net::redirect_error(Net::use_awaitable, Error));
        }
        if (Error)
        {
            Complete();
            co_return;
        }
        {
            std::lock_guard Lock(Mutex_);
            Captured_ = std::move(Captured);
        }

        if (!Error)
        {
            std::array<char, 4096> Buffer{};
            Net::steady_timer Timer(Socket->get_executor());
            using Net::experimental::awaitable_operators::operator||;
            Timer.expires_after(std::chrono::milliseconds(80));
            while (true)
            {
                boost::system::error_code ReadError;
                auto Read = [&]() -> Net::awaitable<std::size_t>
                {
                    co_return co_await Socket->async_read_some(Net::buffer(Buffer),
                        Net::redirect_error(Net::use_awaitable, ReadError));
                };
                auto Wait = [&]() -> Net::awaitable<void>
                {
                    boost::system::error_code TimerError;
                    co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, TimerError));
                };
                const auto Result = co_await (Read() || Wait());
                if (Result.index() == 1U)
                {
                    break;
                }
                const auto Count = std::get<0>(Result);
                if (ReadError)
                {
                    break;
                }
                {
                    std::lock_guard Lock(Mutex_);
                    Extra_.append(Buffer.data(), Count);
                }
                Timer.expires_after(std::chrono::milliseconds(80));
            }
        }

        if (!Response_.empty())
        {
            co_await Net::async_write(*Socket, Net::buffer(Response_),
                Net::redirect_error(Net::use_awaitable, Error));
        }
        MarkResponseSent(!Error);
        if (Error)
        {
            Complete();
            co_return;
        }
        if (!PostResponseExpected_.empty())
        {
            std::string Captured(PostResponseExpected_.size(), '\0');
            co_await Net::async_read(*Socket, Net::buffer(Captured),
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                Complete();
                co_return;
            }
            {
                std::lock_guard Lock(Mutex_);
                PostResponseCaptured_ = std::move(Captured);
            }
        }
        if (CloseMode_ == OriginCloseMode::KeepOpen)
        {
            HoldTimer_.expires_at(std::chrono::steady_clock::time_point::max());
            boost::system::error_code HoldError;
            co_await HoldTimer_.async_wait(Net::redirect_error(Net::use_awaitable, HoldError));
        }
        Socket->shutdown(Tcp::socket::shutdown_both, Error);
        Socket->close(Error);
        Complete();
    }

    inline auto LoopbackOrigin::Complete() -> void
    {
        {
            std::lock_guard Lock(Mutex_);
            Completed_ = true;
        }
        Condition_.notify_all();
    }

    inline auto LoopbackOrigin::MarkResponseSent(const bool Succeeded) -> void
    {
        {
            std::lock_guard Lock(Mutex_);
            ResponseSent_ = Succeeded;
        }
        Condition_.notify_all();
    }
} // namespace Prism::Testing::HttpForward
