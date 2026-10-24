/**
 * @file Exchange.hpp
 * @brief DNS 上游单次收发、尝试请求与连接池交换细节
 * @details 只负责 Link 的 Send/Receive、尝试级绝对 deadline 和池化连接复用；
 *          查询报文解析、RCODE 和 Fallback/First/Fastest 策略由 Upstream 负责。
 */

#pragma once

#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/errc.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Dns/Answer.hpp>
#include <Prism/Net/Dns/ConnPool.hpp>
#include <Prism/Net/Dns/QueryIdentity.hpp>
#include <Prism/Net/Dns/Transport.hpp>
#include <Prism/Net/Dns/UpstreamTypes.hpp>

namespace Prism::Network::Dns::Detail
{

    /**
     * @struct AttemptRequest
     * @brief 单次上游尝试的借用输入
     * @details 服务器配置与查询身份只借用到本次尝试完成；UDP、TCP、DoT 与
     *          DoH 共享这里的同一个绝对 deadline，任何一段都不重置预算。
     */
    struct AttemptRequest
    {
        const Server &ServerConfig;           ///< 上游配置（借用到尝试完成）
        std::span<const std::uint8_t> Wire;   ///< 已编码查询报文（借用到尝试完成）
        const QueryIdentity &Identity;        ///< 查询身份（借用到尝试完成）
        AttemptDeadline Deadline;             ///< 本次尝试的绝对截止时刻
    };

    /**
     * @brief 把应答校验失败映射到 DNS 传输结果，并保留池额度或原生失败身份。
     * @param Failure CheckAnswers 返回的同步失败值
     * @return DNS 对外错误码；原生 category/value 不经消息转换
     */
    [[nodiscard]] inline auto CheckedAnswerErrorCode(const Fault::Failure &Failure) noexcept
        -> boost::system::error_code
    {
        if (Failure.Native)
        {
            const auto &Native = Failure.Native;
            if (Native.category() == Prism::ErrorCategory())
            {
                return Prism::make_error_code(static_cast<Prism::Error>(Native.value()));
            }
            if (Native.category() == Fault::Category())
            {
                return boost::system::make_error_code(static_cast<Fault::Code>(Native.value()));
            }
            if (Native.category() == std::generic_category())
            {
                return {Native.value(), boost::system::generic_category()};
            }
            if (Native.category() == std::system_category())
            {
                return {Native.value(), boost::system::system_category()};
            }
            return boost::system::error_code(Native);
        }
        if (Failure.Code == Fault::Code::ProtocolError)
        {
            return Prism::make_error_code(Prism::Error::BadMessage);
        }
        return boost::system::make_error_code(Failure.Code);
    }

    /**
     * @brief 池化交换请求参数
     * @tparam Link 可池化的 DNS 传输
     */
    template <PoolableTransport Link>
    struct PooledExchangeRequest
    {
        ConnPool<Link> &Pool;
        std::string Key;
        boost::asio::ip::tcp::endpoint Endpoint;
        const Server &ServerConfig;
        std::span<const std::uint8_t> Wire;
        CheckedAnswerRequest CheckedAnswer;
        AttemptDeadline Deadline;
    };

    /**
     * @brief 判断 pooled I/O 失败是否属于当前查询的终态取消或超时。
     * @param ErrorCode 原始传输错误
     * @return 取消或超时返回 true；其他传输失败仍允许旧连接的一次重拨
     */
    [[nodiscard]] inline auto IsCancellationOrTimeout(
        const boost::system::error_code &ErrorCode) noexcept -> bool
    {
        if (ErrorCode == boost::asio::error::operation_aborted ||
            ErrorCode == boost::asio::error::timed_out ||
            ErrorCode == Prism::make_error_code(Prism::Error::Canceled) ||
            ErrorCode == Prism::make_error_code(Prism::Error::Timeout) ||
            ErrorCode == boost::system::make_error_code(Prism::Fault::Code::Canceled) ||
            ErrorCode == boost::system::make_error_code(Prism::Fault::Code::Timeout))
        {
            return true;
        }
        const auto Condition = ErrorCode.default_error_condition();
        return Condition == boost::system::errc::make_error_condition(
                               boost::system::errc::operation_canceled) ||
               Condition == boost::system::errc::make_error_condition(
                               boost::system::errc::timed_out);
    }

    /**
     * @brief 验证失败时尝试关闭链路，清理异常不覆盖原始结果。
     * @param LinkObject 当前已移出池的链路
     */
    template <PoolableTransport Link>
    auto CloseFailedPooledLink(Link &LinkObject) noexcept -> void
    {
        try
        {
            LinkObject.Close();
        }
        catch (...)
        {
        }
    }

    /**
     * @brief 校验已收到的完整 DNS 应答；失败时关闭承载且返回精确错误。
     * @param LinkObject 当前承载；校验失败时由本函数关闭
     * @param Wire 已接收的 DNS 字节；同步借用到校验返回
     * @param Request 当前 query 身份和真实有界池
     * @return 完整拥有的正式答案或精确保留的校验错误
     * @details 校验抛出（包括分配异常）时先尝试关闭，再原样重抛；调用方不会将链路归还池。
     */
    template <PoolableTransport Link>
    [[nodiscard]] inline auto CheckPooledResponse(Link &LinkObject,
                                                   const std::vector<std::uint8_t> &Wire,
                                                   const CheckedAnswerRequest Request)
        -> EcResult<AnswerSet>
    {
        try
        {
            auto Checked = CheckAnswers(Wire, Request);
            if (!Checked)
            {
                CloseFailedPooledLink(LinkObject);
                return std::unexpected(CheckedAnswerErrorCode(Checked.error()));
            }
            return std::move(*Checked);
        }
        catch (...)
        {
            CloseFailedPooledLink(LinkObject);
            throw;
        }
    }

    /**
     * @brief 在已连接 Link 上完成一次发送和接收
     * @param LinkObject 已连接传输
     * @param Wire DNS 查询报文；只借用到本次尝试完成
     * @param Deadline 本次尝试的绝对截止时刻
     * @return DNS 应答字节或传输错误
     */
    template <typename Link>
    [[nodiscard]] inline auto ExchangeOnce(Link &LinkObject, std::span<const std::uint8_t> Wire,
                                           const AttemptDeadline Deadline)
        -> boost::asio::awaitable<EcResult<std::vector<std::uint8_t>>>
    {
        if (auto ErrorCode = co_await LinkObject.Send(Wire, Deadline))
        {
            co_return std::unexpected(ErrorCode);
        }
        co_return co_await LinkObject.Receive(Deadline);
    }

    /**
     * @brief 池化交换：复用连接发生普通传输失败时重试一次，校验成功后才归还连接
     * @tparam Link 可池化的 DNS 传输
     * @tparam Factory 建连工厂
     * @param Request 池化交换参数（含共用绝对 deadline）
     * @param MakeLink 建连工厂
     * @return 已校验并拥有的 DNS 答案或传输、校验错误
     * @details 取消、超时与 DNS 身份/报文失败关闭并返回；只有其他旧连接传输失败会重拨一次。
     */
    template <PoolableTransport Link, typename Factory>
    [[nodiscard]] inline auto ExchangePooled(PooledExchangeRequest<Link> Request, Factory MakeLink)
        -> boost::asio::awaitable<EcResult<AnswerSet>>
    {
        if (Request.ServerConfig.KeepAlive)
        {
            auto Lease = Request.Pool.Acquire(Request.Key);
            if (Lease.Conn)
            {
                auto Result = co_await ExchangeOnce(*Lease.Conn, Request.Wire, Request.Deadline);
                if (Result)
                {
                    auto Checked = CheckPooledResponse(*Lease.Conn, *Result, Request.CheckedAnswer);
                    if (!Checked)
                    {
                        co_return std::unexpected(Checked.error());
                    }
                    Request.Pool.Release(Request.Key, Lease.Conn);
                    co_return std::move(*Checked);
                }
                Lease.Conn->Close();
                if (IsCancellationOrTimeout(Result.error()))
                {
                    co_return std::unexpected(Result.error());
                }
            }
        }

        auto Fresh = co_await MakeLink(Request.Endpoint, Request.ServerConfig);
        if (!Fresh)
        {
            co_return std::unexpected(Fresh.error());
        }
        auto Result = co_await ExchangeOnce(**Fresh, Request.Wire, Request.Deadline);
        if (!Result)
        {
            (*Fresh)->Close();
            co_return std::unexpected(Result.error());
        }
        auto Checked = CheckPooledResponse(**Fresh, *Result, Request.CheckedAnswer);
        if (!Checked)
        {
            co_return std::unexpected(Checked.error());
        }
        if (Request.ServerConfig.KeepAlive)
        {
            Request.Pool.Release(Request.Key, *Fresh);
        }
        co_return std::move(*Checked);
    }

} // namespace Prism::Network::Dns::Detail
