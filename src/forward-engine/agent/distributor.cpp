#include <agent/distributor.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <stdexcept>
#include <abnormal.hpp>

namespace ngx::agent
{
   distributor::distributor(source &pool, net::io_context &ioc, memory::resource_pointer mr)
       : pool_(pool), resolver_(ioc), mr_(mr ? mr : memory::current_resource()), reverse_map_(mr_)
   {
   }

   void distributor::load_reverse_map(const std::string &file_path)
   {
      boost::property_tree::ptree pt;
      boost::property_tree::read_json(file_path, pt);

      reverse_map_.clear();

      const auto addressable_host = pt.get<std::string>("agent.addressable.host", "");
      const auto addressable_port = pt.get<unsigned short>("agent.addressable.port", 0);

      if (!addressable_host.empty() && addressable_port != 0)
      {
         boost::system::error_code ec;
         const auto address = net::ip::make_address(addressable_host, ec);
         if (!ec)
         {
            std::string incoming_host = pt.get<std::string>("agent.positive.host", "");
            if (incoming_host.empty())
            {
               incoming_host = "localhost";
            }

            memory::string host_key(mr_);
            host_key.assign(incoming_host);
            reverse_map_.emplace(std::move(host_key), tcp::endpoint(address, addressable_port));
         }
      }

      if (const auto reverse_map_node = pt.get_child_optional("agent.reverse_map"))
      {
         for (const auto &[incoming_host, backend_node] : *reverse_map_node)
         {
            const auto backend_host = backend_node.get<std::string>("host", "");
            const auto backend_port = backend_node.get<unsigned short>("port", 0);

            if (incoming_host.empty() || backend_host.empty() || backend_port == 0)
            {
               continue;
            }

            boost::system::error_code ec;
            const auto address = net::ip::make_address(backend_host, ec);
            if (ec)
            {
               continue;
            }

            memory::string host_key(mr_);
            host_key.assign(incoming_host);
            reverse_map_.insert_or_assign(std::move(host_key), tcp::endpoint(address, backend_port));
         }
      }
   }

   /**
    * @brief 给 HTTP 正向代理用 (查 DNS)
    * @param host 目标主机名
   * @param port 目标端口号
   * @return 一个指向内部连接对象的智能指针
   */
   net::awaitable<exclusive_connection> distributor::route_forward(const std::string_view host, const std::string_view port)
   {
      // 1. 查 DNS
      if (blacklist_.domain(host))
      {
         throw abnormal::network(std::format("Domain blacklisted: {}, port: {}",host,port));
      }
      const auto results = co_await resolver_.async_resolve(host, port, net::use_awaitable);
      // 2. 找池子要连接
      co_return co_await pool_.acquire_tcp(*results.begin());
   }

   /**
    * @brief 给 HTTP 反向代理用 (查静态表)
   * @param host 目标主机名
   * @return 一个指向内部连接对象的智能指针
   */
   net::awaitable<exclusive_connection> distributor::route_reverse(const std::string_view host)
   {
      // 1. 查配置表 (比如 configuration.json 加载进来的 map)
      if (auto it = reverse_map_.find(host); it != reverse_map_.end())
      {
         co_return co_await pool_.acquire_tcp(it->second);
      }
      throw abnormal::network("Unknown host: {}", std::string_view(host));
   }

   /**
    * @brief 直接连接到指定的 IP 地址
    * @param ep 目标 IP 地址和端口
    * @return 一个指向内部连接对象的智能指针
    */
   net::awaitable<exclusive_connection> distributor::route_direct(const tcp::endpoint ep) const
   {
      co_return co_await pool_.acquire_tcp(ep);
   }

}
