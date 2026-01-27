#include <forward-engine/agent/distributor.hpp>
#include <abnormal.hpp>

namespace ngx::agent
{
    using tcp = boost::asio::ip::tcp;

   distributor::distributor(source &pool, net::io_context &ioc, memory::resource_pointer mr)
       : pool_(pool), resolver_(ioc), mr_(mr ? mr : memory::current_resource()), reverse_map_(mr_)
   {
   }

   void distributor::add_reverse_route(std::string_view host, const tcp::endpoint& ep)
   {
       memory::string host_key(mr_);
       host_key.assign(host);
       reverse_map_.insert_or_assign(std::move(host_key), ep);
   }

   /**
    * @brief HTTP 正向代理 (DNS)
    * @param host 目标主机
    * @param port 目标端口
    * @return 状态码与连接对象的 pair
    */
   auto distributor::route_forward(const std::string_view host, const std::string_view port)
      -> net::awaitable<std::pair<gist::code, exclusive_connection>>
   {
      // 1. DNS
      if (blacklist_.domain(host))
      {
         co_return route_result{gist::code::blocked, nullptr};
      }
      boost::system::error_code ec;
      auto results = co_await resolver_.async_resolve(host, port, net::redirect_error(net::use_awaitable, ec));
      if (ec)
      {
         co_return route_result{gist::code::host_unreachable, nullptr};
      }
      if (results.empty())
      {
         co_return route_result{gist::code::host_unreachable, nullptr};
      }
      // 2. 找池子要连接
      auto conn = co_await pool_.acquire_tcp(*results.begin());
      co_return route_result{gist::code::success, std::move(conn)};
   }

   /**
    * @brief HTTP 反向代理 (查静态表)
    * @param host 目标主机
    * @return 状态码与连接对象的 pair
    */
   auto distributor::route_reverse(const std::string_view host)
      -> net::awaitable<std::pair<gist::code, exclusive_connection>>
   {
      // 1. 查配置表
      if (auto it = reverse_map_.find(host); it != reverse_map_.end())
      {
         auto conn = co_await pool_.acquire_tcp(it->second);
         co_return route_result{gist::code::success, std::move(conn)};
      }
      co_return route_result{gist::code::bad_gateway, nullptr};
   }

   /**
    * @brief 直接连接到指定的 IP 地址
    * @param ep 目标 IP 地址和端口
    * @return 状态码与连接对象的 pair
    */
   auto distributor::route_direct(const tcp::endpoint ep) const
      -> net::awaitable<std::pair<gist::code, exclusive_connection>>
   {
      auto conn = co_await pool_.acquire_tcp(ep);
      co_return route_result{gist::code::success, std::move(conn)};
   }

}
