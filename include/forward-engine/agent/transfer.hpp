#pragma once

#include <cstddef>
#include <cctype>

#include <array>
#include <memory>
#include <string>
#include <format>
#include <utility>
#include <iostream>
#include <functional>
#include <string_view>

#include <memory/pool.hpp>

#include <boost/asio.hpp>
#include <abnormal.hpp>
#include "analysis.hpp"
#include "obscura.hpp"
#include "source.hpp"

#include <boost/asio/experimental/awaitable_operators.hpp>


namespace ngx::agent::tunnel
{
    class context
    {

        std::function<void(level, const std::string_view)> trace;
    };

    struct transfer
    {
        template <typename Source, typename Dest>
        net::awaitable<void> transfer_tcp(Source& source, Dest& dest,boost::asio::mutable_buffer buffer)
        {
            boost::system::error_code ec;
            auto token = net::redirect_error(net::use_awaitable, ec);
            while (true)
            {
                ec.clear();
                const std::size_t n = co_await from.async_read_some(buffer, token);
                if (ec)
                {
                    if (graceful(ec))
                    {   // 对端正常关闭或被取消
                        shut_close(to);
                        co_return;
                    }
                    throw abnormal::network("transfer_tcp 读失败: {}", ec.message());
                }

                if (n == 0)
                {   // 对端正常关闭
                    shut_close(to);
                    co_return;
                }

                ec.clear();
                co_await net::async_write(to, net::buffer(buffer.data(), n), token);
                if (ec)
                {
                    if (graceful(ec))
                    {
                        shut_close(from);
                        co_return;
                    }
                    throw abnormal::network("transfer_tcp 写失败: {}", ec.message());
                }
            }
        }
    };
}