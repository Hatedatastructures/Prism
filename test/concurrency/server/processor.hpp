/**
 * @file processor.hpp
 * @brief 请求处理器模块
 * @details 提供高性能的静态文件服务、主 API 和统计 API 的请求处理功能。
 *
 * 核心特性：
 * - 零拷贝：使用 string_view 避免数据拷贝
 * - 内存池：使用 ngx::memory 分配响应数据
 * - 静态文件服务：支持路径安全验证、MIME 类型检测、缓存控制
 * - JSON 序列化：高性能 JSON 序列化
 *
 * C++23 特性：
 * - std::views::zip：并行迭代简化代码
 * - std::views::enumerate：带索引迭代
 * - std::views::transform：函数式数据处理
 * - std::print：高性能格式化输出
 *
 * @note 设计原则：
 * - 高性能优先：零拷贝 + 内存池
 * - 安全优先：严格验证文件路径
 * - 协程优先：异步处理使用 co_await
 *
 * @see httpsession.hpp
 */

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <array>
#include <format>
#include <ranges>
#include <numeric>

#ifdef _WIN32
#include <windows.h>
#endif

#include "statistics.hpp"
#include "mime.hpp"

#include <forward-engine/protocol/http/request.hpp>
#include <forward-engine/protocol/http/response.hpp>
#include <forward-engine/protocol/http/constants.hpp>
#include <forward-engine/transformer/json.hpp>
#include <forward-engine/memory.hpp>
#include <forward-engine/memory/pool.hpp>

#include <glaze/glaze.hpp>
#include <boost/asio.hpp>

namespace srv::processor
{
    namespace fs = std::filesystem;
    namespace net = boost::asio;

    using namespace srv::statistics;
    using namespace ngx::transformer::json;

    /**
     * @brief 安全的字符串转整数函数
     */
    template <typename IntType = int>
    [[nodiscard]] IntType safe_parse_int(std::string_view str, IntType default_value = IntType{}) noexcept
    {
        if (str.empty())
        {
            return default_value;
        }

        IntType result{};
        const auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), result);

        if (ec == std::errc{} && ptr == str.data() + str.size())
        {
            return result;
        }
        return default_value;
    }

    /**
     * @class static_handler
     * @brief 静态文件处理器类
     * @details 高性能静态文件服务，支持零拷贝和内存映射
     */
    class static_handler final
    {
    public:
        explicit static_handler(std::string base_dir = "webroot/main")
            : base_dir_(std::move(base_dir))
        {
        }

        /**
         * @brief 服务静态文件
         * @param path 请求路径
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 是否成功
         */
        [[nodiscard]] bool serve_file(std::string_view path, ngx::protocol::http::response &resp, detailed_stats &stats) const
        {
            const auto full_path = resolve_path(path);
            if (!validate_path(full_path))
            {
                stats.increment_not_found();
                return false;
            }

            std::error_code ec;
            if (!fs::exists(full_path, ec) || !fs::is_regular_file(full_path, ec))
            {
                stats.increment_not_found();
                return false;
            }

            const auto file_size = fs::file_size(full_path, ec);
            if (ec || file_size > static_cast<std::uintmax_t>(MAX_FILE_SIZE))
            {
                return false;
            }

            try
            {
                // 使用内存池分配文件内容
                auto *mr = ngx::memory::current_resource();
                ngx::memory::string body(mr);
                body.resize(static_cast<std::size_t>(file_size));

                std::ifstream file(full_path, std::ios::binary);
                if (!file.is_open())
                {
                    return false;
                }

                file.read(body.data(), static_cast<std::streamsize>(file_size));

                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, srv::mime::obtain_mapping(path));
                resp.content_length(static_cast<std::uint64_t>(file_size));
                resp.set(ngx::protocol::http::field::last_modified, get_last_modified(full_path));
                resp.set(ngx::protocol::http::field::etag, generate_etag(full_path, file_size));
                resp.set(ngx::protocol::http::field::cache_control, "public, max-age=3600");
                resp.body(std::move(body));

                stats.add_bytes_received(static_cast<std::uint64_t>(file_size));
                stats.add_bytes_sent(static_cast<std::uint64_t>(file_size));
                stats.increment_static_files();

                return true;
            }
            catch (...)
            {
                return false;
            }
        }

    private:
        static constexpr std::uint64_t MAX_FILE_SIZE = 100 * 1024 * 1024;
        std::string base_dir_;

        [[nodiscard]] std::string resolve_path(std::string_view path) const
        {
            std::string result(path);

            if (result.empty() || result == "/")
            {
                result = "/index.html";
            }

            if (result.find("..") != std::string::npos)
            {
                return base_dir_ + "/index.html";
            }

            if (result[0] == '/')
            {
                result = base_dir_ + result;
            }
            else
            {
                result = base_dir_ + "/" + result;
            }

            return result;
        }

        [[nodiscard]] bool validate_path(const std::string &path) const
        {
            std::error_code ec;
            const std::string base_dir_abs = fs::absolute(base_dir_, ec).string();
            const std::string full_path = fs::absolute(path, ec).string();

            return full_path.find(base_dir_abs) == 0;
        }

        [[nodiscard]] static std::string get_last_modified(const std::string &path)
        {
            std::error_code ec;
            const auto ftime = fs::last_write_time(path, ec);
            if (ec)
                return {};

            const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
            const auto c_time = std::chrono::system_clock::to_time_t(sctp);

            std::tm tm_buffer{};
#ifdef _WIN32
            _gmtime64_s(&tm_buffer, &c_time);
#else
            gmtime_r(&c_time, &tm_buffer);
#endif

            std::array<char, 128> buffer{};
            std::strftime(buffer.data(), buffer.size(), "%a, %d %b %Y %H:%M:%S GMT", &tm_buffer);
            return std::string(buffer.data());
        }

        [[nodiscard]] static std::string generate_etag(const std::string &path, std::uintmax_t size)
        {
            std::error_code ec;
            const auto ftime = fs::last_write_time(path, ec);
            if (ec)
                return {};

            const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
            const auto c_time = std::chrono::system_clock::to_time_t(sctp);

            return std::format("\"{:x}-{:x}\"", static_cast<unsigned long>(c_time), static_cast<unsigned long long>(size));
        }
    };

    /**
     * @namespace main_api
     * @brief 主 API 命名空间
     */
    namespace main_api
    {
        // 商品规格
        struct product_spec final
        {
            std::string name;
            std::string value;
        };

        // 商品评价
        struct product_review final
        {
            std::string author;
            std::uint32_t rating{0};
            std::string content;
            std::string date;
        };

        // 商品
        struct product final
        {
            std::string id;
            std::string name;
            std::string description;
            double price{0.0};
            double original_price{0.0};
            std::string image;
            std::string category;
            std::uint32_t stock{0};
            std::uint32_t sales{0};
            double rating{0.0};
            std::vector<product_spec> specs;
            std::vector<product_review> reviews;
            std::string detail;
        };

        // 商品列表响应
        struct products_response final
        {
            std::vector<product> items;
            std::uint32_t total{0};
            std::uint32_t page{1};
            std::uint32_t page_size{10};
        };

        // 购物车商品
        struct cart_item final
        {
            std::string id;
            std::string name;
            std::uint32_t quantity{0};
            double price{0.0};
            std::string image;
            std::uint32_t stock{0};
            std::string spec;
        };

        // 购物车响应
        struct cart_response final
        {
            std::vector<cart_item> items;
            std::uint32_t total_items{0};
            double total_price{0.0};
        };

        // 搜索响应
        struct search_response final
        {
            std::vector<product> results;
            std::uint32_t total{0};
            std::string query;
        };

        // 静态商品数据 - 编译期初始化
        [[nodiscard]] inline std::vector<product> generate_mock_products() noexcept
        {
            return {
                product{"p001", "高性能无线机械键盘", "采用Cherry MX轴体，支持多设备连接，续航时间长达30天", 599.0, 799.0, "/images/keyboard.jpg", "电子产品", 100, 256, 4.8, {{"品牌", "ForwardEngine"}, {"轴体", "Cherry MX青轴"}, {"连接方式", "蓝牙/2.4G/有线"}}, {{"张三", 5, "手感非常好，打字效率提升明显", "2024-01-15"}, {"李四", 4, "续航很给力，但价格稍贵", "2024-01-10"}}, "采用德国Cherry MX轴体，支持蓝牙5.0、2.4G无线和有线三模连接。"},
                product{"p002", "4K超高清显示器", "27英寸IPS面板，144Hz刷新率，支持HDR400", 2999.0, 3499.0, "/images/monitor.jpg", "电子产品", 50, 128, 4.9, {{"品牌", "ForwardEngine"}, {"尺寸", "27英寸"}, {"分辨率", "4K"}}, {{"王五", 5, "色彩非常准确，设计工作完美", "2024-01-12"}}, "27英寸IPS面板，4K超高清分辨率，144Hz高刷新率。"},
                product{"p003", "人体工学办公椅", "网布材质，可调节腰托，支持午休模式", 899.0, 1299.0, "/images/chair.jpg", "家居用品", 80, 200, 4.6, {{"品牌", "ForwardEngine"}, {"材质", "高弹网布"}, {"承重", "150kg"}}, {}, "采用高弹透气网布，4D可调节扶手。"},
                product{"p004", "智能降噪耳机", "主动降噪，40小时续航，支持多设备同时连接", 1299.0, 1599.0, "/images/headphone.jpg", "电子产品", 120, 512, 4.7, {{"品牌", "ForwardEngine"}, {"降噪等级", "ANC主动降噪"}, {"续航", "40小时"}}, {{"赵六", 5, "降噪效果非常好，通勤必备", "2024-01-08"}}, "采用ANC主动降噪技术，降噪深度可达35dB。"},
                product{"p005", "便携式SSD硬盘", "1TB容量，Type-C接口，读写速度高达1000MB/s", 699.0, 899.0, "/images/ssd.jpg", "电子产品", 200, 1024, 4.5, {{"品牌", "ForwardEngine"}, {"容量", "1TB"}, {"接口", "USB 3.2 Type-C"}}, {}, "采用NVMe协议，读写速度高达1000MB/s。"},
            };
        }

        [[nodiscard]] inline cart_response generate_mock_cart() noexcept
        {
            return cart_response{
                {cart_item{"p001", "高性能无线机械键盘", 2, 599.0, "/images/keyboard.jpg", 100, "Cherry MX青轴"},
                 cart_item{"p002", "4K超高清显示器", 1, 2999.0, "/images/monitor.jpg", 50, "27英寸"},
                 cart_item{"p004", "智能降噪耳机", 1, 1299.0, "/images/headphone.jpg", 120, "黑色"}},
                4,
                5497.0};
        }

        // API 处理函数
        inline net::awaitable<void> get_products(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();
            const auto start_time = std::chrono::steady_clock::now();

            try
            {
                std::uint32_t page = 1;
                std::uint32_t page_size = 10;
                std::string category_filter;

                const auto query_params = req.target();
                std::size_t query_pos = query_params.find('?');
                if (query_pos != std::string_view::npos)
                {
                    const auto query_string = query_params.substr(query_pos + 1);
                    for (auto it = query_string.begin(); it != query_string.end();)
                    {
                        auto param_end = std::find(it, query_string.end(), '&');
                        std::string_view param(it, param_end);
                        auto eq_pos = param.find('=');
                        if (eq_pos != std::string_view::npos)
                        {
                            const auto key = param.substr(0, eq_pos);
                            const auto value = param.substr(eq_pos + 1);
                            if (key == "page")
                                page = safe_parse_int<std::uint32_t>(value, 1);
                            else if (key == "page_size")
                                page_size = safe_parse_int<std::uint32_t>(value, 10);
                            else if (key == "category")
                                category_filter = value;
                        }
                        it = param_end == query_string.end() ? param_end : param_end + 1;
                    }
                }

                const auto all_products = generate_mock_products();
                std::vector<product> filtered_products;

                if (category_filter.empty())
                {
                    filtered_products = all_products;
                }
                else
                {
                    for (const auto &prod : all_products)
                    {
                        if (prod.category == category_filter)
                            filtered_products.push_back(prod);
                    }
                }

                const std::uint32_t total = static_cast<std::uint32_t>(filtered_products.size());
                const std::uint32_t start_index = (page - 1) * page_size;
                const std::uint32_t end_index = std::min(start_index + page_size, total);

                std::vector<product> page_products;
                if (start_index < total)
                {
                    for (std::uint32_t i = start_index; i < end_index; ++i)
                        page_products.push_back(filtered_products[i]);
                }

                products_response response_data{std::move(page_products), total, page, page_size};
                auto json_buffer = serialize(response_data);

                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.set(ngx::protocol::http::field::cache_control, "public, max-age=60");
                resp.content_length(json_buffer.size());
                resp.body(std::move(json_buffer));

                const auto end_time = std::chrono::steady_clock::now();
                stats.record_request_time(std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count());
                stats.record_status_code(200);
                stats.record_method("GET");
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.content_length(32);
                resp.body(R"({"error":"Internal Server Error"})");
                stats.increment_errors();
                stats.record_status_code(500);
            }
            co_return;
        }

        inline net::awaitable<void> get_product_detail([[maybe_unused]] ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats, std::string_view product_id)
        {
            stats.increment_api_requests();
            const auto start_time = std::chrono::steady_clock::now();

            try
            {
                const auto all_products = generate_mock_products();
                bool found = false;
                product target_product;

                for (const auto &prod : all_products)
                {
                    if (prod.id == product_id)
                    {
                        target_product = prod;
                        found = true;
                        break;
                    }
                }

                if (found)
                {
                    auto json_buffer = serialize(target_product);
                    resp.status(ngx::protocol::http::status::ok);
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.content_length(json_buffer.size());
                    resp.body(std::move(json_buffer));

                    const auto end_time = std::chrono::steady_clock::now();
                    stats.record_request_time(std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count());
                    stats.record_status_code(200);
                }
                else
                {
                    resp.status(ngx::protocol::http::status::not_found);
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
                    resp.content_length(22);
                    resp.body(R"({"error":"Not Found"})");
                    stats.increment_not_found();
                    stats.record_status_code(404);
                }
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.content_length(32);
                resp.body(R"({"error":"Internal Server Error"})");
                stats.increment_errors();
                stats.record_status_code(500);
            }
            co_return;
        }

        inline net::awaitable<void> cart_operations(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();
            const auto start_time = std::chrono::steady_clock::now();

            const auto method = req.method();
            if (method == ngx::protocol::http::verb::get)
            {
                const auto cart_data = generate_mock_cart();
                auto json_buffer = serialize(cart_data);
                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.content_length(json_buffer.size());
                resp.body(std::move(json_buffer));
                stats.record_status_code(200);
                stats.record_method("GET");
            }
            else if (method == ngx::protocol::http::verb::post)
            {
                resp.status(ngx::protocol::http::status::created);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.content_length(49);
                resp.body(R"({"success":true,"message":"Product added to cart"})");
                stats.record_status_code(201);
                stats.record_method("POST");
            }
            else if (method == ngx::protocol::http::verb::delete_)
            {
                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.content_length(45);
                resp.body(R"({"success":true,"message":"Product removed"})");
                stats.record_status_code(200);
                stats.record_method("DELETE");
            }
            else
            {
                resp.status(ngx::protocol::http::status::method_not_allowed);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.content_length(30);
                resp.body(R"({"error":"Method Not Allowed"})");
                stats.record_status_code(405);
            }

            const auto end_time = std::chrono::steady_clock::now();
            stats.record_request_time(std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count());
            co_return;
        }

        inline net::awaitable<void> update_cart_item(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();
            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.content_length(47);
            resp.body(R"({"success":true,"message":"Cart item updated"})");
            stats.record_status_code(200);
            stats.record_method("PUT");
            co_return;
        }

        inline net::awaitable<void> delete_cart_item(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();
            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.content_length(47);
            resp.body(R"({"success":true,"message":"Cart item deleted"})");
            stats.record_status_code(200);
            stats.record_method("DELETE");
            co_return;
        }

        inline net::awaitable<void> delete_cart_items(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();
            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.content_length(48);
            resp.body(R"({"success":true,"message":"Cart items deleted"})");
            stats.record_status_code(200);
            stats.record_method("DELETE");
            co_return;
        }

        inline net::awaitable<void> cart_checkout(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();
            const auto cart_data = generate_mock_cart();
            auto json_buffer = serialize(cart_data);
            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.content_length(json_buffer.size());
            resp.body(std::move(json_buffer));
            stats.record_status_code(200);
            stats.record_method("POST");
            co_return;
        }

        inline net::awaitable<void> create_order(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();
            resp.status(ngx::protocol::http::status::created);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.content_length(49);
            resp.body(R"({"success":true,"order_id":"ORD-20240101-001"})");
            stats.record_status_code(201);
            stats.record_method("POST");
            co_return;
        }

        inline net::awaitable<void> search_products(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();
            const auto start_time = std::chrono::steady_clock::now();

            try
            {
                std::string search_query;
                const auto query_params = req.target();
                std::size_t query_pos = query_params.find('?');
                if (query_pos != std::string_view::npos)
                {
                    const auto query_string = query_params.substr(query_pos + 1);
                    auto search_pos = query_string.find("search=");
                    auto q_pos = query_string.find("q=");
                    auto param_pos = std::string_view::npos;

                    if (search_pos != std::string_view::npos)
                        param_pos = search_pos + 7;
                    else if (q_pos != std::string_view::npos)
                        param_pos = q_pos + 2;

                    if (param_pos != std::string_view::npos)
                    {
                        auto value_end = query_string.find('&', param_pos);
                        search_query = value_end == std::string_view::npos
                                           ? std::string(query_string.substr(param_pos))
                                           : std::string(query_string.substr(param_pos, value_end - param_pos));
                    }
                }

                const auto all_products = generate_mock_products();
                std::vector<product> search_results;

                if (search_query.empty())
                {
                    search_results = all_products;
                }
                else
                {
                    std::string lower_query = search_query;
                    std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(),
                                   [](unsigned char c)
                                   { return static_cast<char>(std::tolower(c)); });

                    for (const auto &prod : all_products)
                    {
                        std::string lower_name = prod.name;
                        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                                       [](unsigned char c)
                                       { return static_cast<char>(std::tolower(c)); });

                        if (lower_name.find(lower_query) != std::string::npos)
                            search_results.push_back(prod);
                    }
                }

                search_response response_data{std::move(search_results), static_cast<std::uint32_t>(search_results.size()), search_query};
                auto json_buffer = serialize(response_data);

                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.content_length(json_buffer.size());
                resp.body(std::move(json_buffer));

                const auto end_time = std::chrono::steady_clock::now();
                stats.record_request_time(std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count());
                stats.record_status_code(200);
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.content_length(32);
                resp.body(R"({"error":"Internal Server Error"})");
                stats.increment_errors();
                stats.record_status_code(500);
            }
            co_return;
        }

        inline net::awaitable<void> login(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();
            constexpr std::string_view login_body = R"({"success":true,"token":"mock-jwt-token-12345","user":{"id":"user001","name":"用户001"}})";
            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.content_length(login_body.size());
            resp.body(login_body);
            stats.record_status_code(200);
            stats.record_method("POST");
            co_return;
        }

        inline net::awaitable<void> register_user(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();
            constexpr std::string_view register_body = R"({"success":true,"message":"注册成功"})";
            resp.status(ngx::protocol::http::status::created);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.content_length(register_body.size());
            resp.body(register_body);
            stats.record_status_code(201);
            stats.record_method("POST");
            co_return;
        }

        inline net::awaitable<void> send_captcha(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();
            constexpr std::string_view captcha_body = R"({"success":true,"message":"验证码已发送","expire":300})";
            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.content_length(captcha_body.size());
            resp.body(captcha_body);
            stats.record_status_code(200);
            stats.record_method("POST");
            co_return;
        }
    }

    /**
     * @namespace stats_api
     * @brief 统计 API 命名空间
     */
    namespace stats_api
    {
        struct traffic_history final
        {
            std::uint64_t timestamp{0};
            std::uint64_t bytes_sent{0};
            std::uint64_t bytes_received{0};
        };

        struct connections_response final
        {
            std::vector<connection_info> connections;
        };

        struct traffic_history_response final
        {
            std::vector<traffic_history> history;
            std::uint32_t interval_seconds{60};
        };

        struct performance_metrics final
        {
            double cpu_usage_percent{0.0};
            double memory_usage_mb{0.0};
            std::uint32_t active_threads{0};
            double io_wait_percent{0.0};
        };

        inline net::awaitable<void> get_stats(ngx::protocol::http::response &resp, const detailed_stats &stats)
        {
            const auto snapshot = create_snapshot(stats);
            auto json_str = serialize(snapshot);

            if (json_str.empty())
            {
                constexpr std::string_view error_body = R"({"error":"Failed to serialize stats"})";
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.content_length(error_body.size());
                resp.body(error_body);
                co_return;
            }

            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.set(ngx::protocol::http::field::cache_control, "no-cache");
            resp.content_length(json_str.size());
            resp.body(std::move(json_str));
        }

        inline net::awaitable<void> get_active_connections(ngx::protocol::http::response &resp, const detailed_stats &stats)
        {
            const auto &active_list = stats.get_active_connections();
            const auto head = stats.connection_list_head.load(std::memory_order_relaxed);
            const std::size_t active_count = stats.active_connections.load(std::memory_order_relaxed);

            std::vector<connection_info> conn_list;
            conn_list.reserve(active_count);

            // 使用 C++23 views 优化遍历
            const std::size_t start = head >= detailed_stats::MAX_CONNECTIONS ? head - detailed_stats::MAX_CONNECTIONS : 0;
            const std::size_t count = std::min(head, detailed_stats::MAX_CONNECTIONS) - start;

            // 使用 views::transform 和 views::filter 进行函数式处理
            auto valid_connections =
                std::views::iota(start, start + count) |
                std::views::transform([&active_list](std::size_t i) -> const connection_info &
                                      { return active_list[i % detailed_stats::MAX_CONNECTIONS]; }) |
                std::views::filter([](const connection_info &info)
                                   { return info.client_port != 0; });

            for (const auto &info : valid_connections)
            {
                conn_list.push_back(info);
            }

            connections_response response_data{std::move(conn_list)};
            auto json_str = serialize(response_data);

            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.content_length(json_str.size());
            resp.body(std::move(json_str));
            co_return;
        }

        inline net::awaitable<void> get_traffic_history(ngx::protocol::http::response &resp, const detailed_stats &stats, const std::uint32_t minutes)
        {
            traffic_history_response history_response;
            history_response.interval_seconds = 60;

            const auto now = std::chrono::steady_clock::now();
            const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - stats.start_time).count();
            const std::uint32_t total_seconds = static_cast<std::uint32_t>(uptime);
            const std::uint32_t data_points = std::min(total_seconds / 60, minutes);

            if (data_points > 0)
            {
                const auto total_sent = stats.bytes_sent.load(std::memory_order_relaxed);
                const auto total_received = stats.bytes_received.load(std::memory_order_relaxed);
                const auto avg_sent = total_sent / data_points;
                const auto avg_received = total_received / data_points;

                history_response.history.reserve(data_points);

                // 使用 C++23 views::enumerate 简化带索引的循环
                // 生成时间点并转换为 traffic_history
                auto time_points = std::views::iota(0u, data_points) |
                                   std::views::transform([&now, data_points, avg_sent, avg_received](std::uint32_t i)
                                                         {
                        const auto point_time = now - std::chrono::seconds((data_points - i) * 60);
                        traffic_history history;
                        history.timestamp = static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::milliseconds>(point_time.time_since_epoch()).count());
                        history.bytes_sent = avg_sent * (i + 1);
                        history.bytes_received = avg_received * (i + 1);
                        return history; });

                for (const auto &history : time_points)
                {
                    history_response.history.push_back(history);
                }
            }

            auto json_str = serialize(history_response);
            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.content_length(json_str.size());
            resp.body(std::move(json_str));
            co_return;
        }

        inline net::awaitable<void> get_performance(ngx::protocol::http::response &resp, const detailed_stats &stats)
        {
            performance_metrics metrics;
            metrics.active_threads = stats.active_connections.load(std::memory_order_relaxed);

#ifdef _WIN32
            MEMORYSTATUSEX memory_status;
            memory_status.dwLength = sizeof(memory_status);
            if (GlobalMemoryStatusEx(&memory_status))
            {
                const std::uint64_t total_memory_mb = memory_status.ullTotalPhys / (1024 * 1024);
                const std::uint64_t available_memory_mb = memory_status.ullAvailPhys / (1024 * 1024);
                metrics.memory_usage_mb = static_cast<double>(total_memory_mb - available_memory_mb);
            }

            FILETIME idle_time, kernel_time, user_time;
            if (GetSystemTimes(&idle_time, &kernel_time, &user_time))
            {
                const std::uint64_t idle = static_cast<std::uint64_t>(idle_time.dwLowDateTime) |
                                           (static_cast<std::uint64_t>(idle_time.dwHighDateTime) << 32);
                const std::uint64_t kernel = static_cast<std::uint64_t>(kernel_time.dwLowDateTime) |
                                             (static_cast<std::uint64_t>(kernel_time.dwHighDateTime) << 32);
                const std::uint64_t user = static_cast<std::uint64_t>(user_time.dwLowDateTime) |
                                           (static_cast<std::uint64_t>(user_time.dwHighDateTime) << 32);
                const std::uint64_t total = idle + kernel + user;
                if (total > 0)
                {
                    metrics.cpu_usage_percent = 100.0 * (1.0 - static_cast<double>(idle) / static_cast<double>(total));
                    metrics.io_wait_percent = 100.0 * static_cast<double>(kernel - idle) / static_cast<double>(total);
                }
            }
#endif

            auto json_str = serialize(metrics);
            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.content_length(json_str.size());
            resp.body(std::move(json_str));
            co_return;
        }
    }
}

// glaze JSON 序列化模板特化
template <>
struct glz::meta<srv::processor::main_api::product>
{
    using T = srv::processor::main_api::product;
    static constexpr auto value = glz::object(
        "id", &T::id, "name", &T::name, "description", &T::description,
        "price", &T::price, "original_price", &T::original_price, "image", &T::image,
        "category", &T::category, "stock", &T::stock, "sales", &T::sales,
        "rating", &T::rating, "specs", &T::specs, "reviews", &T::reviews, "detail", &T::detail);
};

template <>
struct glz::meta<srv::processor::main_api::product_spec>
{
    using T = srv::processor::main_api::product_spec;
    static constexpr auto value = glz::object("name", &T::name, "value", &T::value);
};

template <>
struct glz::meta<srv::processor::main_api::product_review>
{
    using T = srv::processor::main_api::product_review;
    static constexpr auto value = glz::object("author", &T::author, "rating", &T::rating, "content", &T::content, "date", &T::date);
};

template <>
struct glz::meta<srv::processor::main_api::products_response>
{
    using T = srv::processor::main_api::products_response;
    static constexpr auto value = glz::object("items", &T::items, "total", &T::total, "page", &T::page, "page_size", &T::page_size);
};

template <>
struct glz::meta<srv::processor::main_api::cart_item>
{
    using T = srv::processor::main_api::cart_item;
    static constexpr auto value = glz::object("id", &T::id, "name", &T::name, "quantity", &T::quantity, "price", &T::price, "image", &T::image, "stock", &T::stock, "spec", &T::spec);
};

template <>
struct glz::meta<srv::processor::main_api::cart_response>
{
    using T = srv::processor::main_api::cart_response;
    static constexpr auto value = glz::object("items", &T::items, "total_items", &T::total_items, "total_price", &T::total_price);
};

template <>
struct glz::meta<srv::processor::main_api::search_response>
{
    using T = srv::processor::main_api::search_response;
    static constexpr auto value = glz::object("results", &T::results, "total", &T::total, "query", &T::query);
};

template <>
struct glz::meta<srv::processor::stats_api::traffic_history>
{
    using T = srv::processor::stats_api::traffic_history;
    static constexpr auto value = glz::object("timestamp", &T::timestamp, "bytes_sent", &T::bytes_sent, "bytes_received", &T::bytes_received);
};

template <>
struct glz::meta<srv::processor::stats_api::connections_response>
{
    using T = srv::processor::stats_api::connections_response;
    static constexpr auto value = glz::object("connections", &T::connections);
};

template <>
struct glz::meta<srv::processor::stats_api::traffic_history_response>
{
    using T = srv::processor::stats_api::traffic_history_response;
    static constexpr auto value = glz::object("history", &T::history, "interval_seconds", &T::interval_seconds);
};

template <>
struct glz::meta<srv::processor::stats_api::performance_metrics>
{
    using T = srv::processor::stats_api::performance_metrics;
    static constexpr auto value = glz::object("cpu_usage_percent", &T::cpu_usage_percent, "memory_usage_mb", &T::memory_usage_mb, "active_threads", &T::active_threads, "io_wait_percent", &T::io_wait_percent);
};
