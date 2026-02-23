/**
 * @file handler.hpp
 * @brief 高性能请求处理器模块
 * @details 基于内存池的零拷贝请求处理，彻底修复悬垂指针漏洞。
 *
 * 核心特性：
 * - 内存池绑定：所有动态响应体必须使用会话内存池分配
 * - 零拷贝：使用 string_view 和内存池分配，避免临时 std::string
 * - 协程优先：所有异步操作使用 co_await
 * - 安全第一：严格遵循内存生命周期铁律
 *
 * 内存安全铁律（绝对不可违反）：
 * 1. 禁止使用 std::to_string() 或临时 std::string 构造数据后直接丢给 response::body(std::string_view)
 * 2. 所有动态响应体必须通过连接的内存池 (ngx::memory::pool*) 分配
 * 3. 所有固定长度响应必须使用 constexpr std::string_view，并在编译期计算 Content-Length
 * 4. 每个请求处理器必须接收内存池指针作为参数
 *
 * @note 设计原则：
 * - 高性能：零拷贝 + 内存池 + 无锁
 * - 内存安全：动态响应体在 async_write 完成前绝对不被释放
 * - 职责单一：仅负责业务逻辑处理，路由匹配由 routing.hpp 负责
 *
 * @see routing.hpp
 * @see session.hpp
 */

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <array>
#include <format>
#include <ranges>
#include <numeric>
#include <filesystem>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#endif

#include "routing.hpp"
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

namespace srv::handler
{
    namespace net = boost::asio;
    using namespace ngx::transformer::json;
    using namespace srv::routing;
    using namespace srv::statistics;

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

    namespace fs = std::filesystem;

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
         * @param pool 内存池指针（可为空，使用当前线程内存池）
         * @return 是否成功
         */
        [[nodiscard]] bool serve_file(std::string_view path, ngx::protocol::http::response &resp, detailed_stats &stats, 
                                     ngx::memory::pool* pool = nullptr) const
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
                auto *mr = pool ? pool->get_allocator().resource() : ngx::memory::current_resource();
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
     * @class handler_base
     * @brief 处理器基类
     * @details 提供通用的内存池管理和响应构建功能。
     */
    class handler_base
    {
    public:
        explicit handler_base(ngx::memory::pool *pool) noexcept
            : pool_(pool)
        {
        }

        virtual ~handler_base() = default;

        /**
         * @brief 使用内存池分配字符串构建 JSON 响应
         * @tparam T 可序列化类型
         * @param data 要序列化的数据
         * @param resp HTTP 响应对象
         * @return bool 是否成功
         */
        template <typename T>
        bool build_json_response(const T &data, ngx::protocol::http::response &resp) noexcept
        {
            try
            {
                // 使用内存池分配字符串
                ngx::memory::string json_body(pool_);
                const auto result = serialize_to_string(data, json_body);
                if (!result)
                {
                    return false;
                }

                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.content_length(json_body.size());
                resp.body(json_body);
                return true;
            }
            catch (...)
            {
                return false;
            }
        }

        /**
         * @brief 构建错误响应（使用编译期字符串）
         * @param status HTTP 状态码
         * @param error_message 错误消息
         * @param resp HTTP 响应对象
         */
        void build_error_response(ngx::protocol::http::status status, std::string_view error_message,
                                  ngx::protocol::http::response &resp) noexcept
        {
            resp.status(status);
            resp.set(ngx::protocol::http::field::content_type, "application/json");

            // 使用内存池分配错误响应体
            ngx::memory::string json_body(pool_);
            json_body.append(R"({"error":")");
            json_body.append(error_message);
            json_body.append(R"("})");

            resp.content_length(json_body.size());
            resp.body(json_body);
        }

        /**
         * @brief 构建固定长度响应（编译期计算）
         * @param status HTTP 状态码
         * @param content_type 内容类型
         * @param body 响应体（必须是 constexpr std::string_view）
         * @param resp HTTP 响应对象
         */
        template <std::size_t N>
        void build_constexpr_response(ngx::protocol::http::status status,
                                      std::string_view content_type,
                                      const char (&body)[N],
                                      ngx::protocol::http::response &resp) noexcept
        {
            resp.status(status);
            resp.set(ngx::protocol::http::field::content_type, content_type);
            resp.content_length(N - 1); // 减去 null 终止符
            resp.body(std::string_view(body, N - 1));
        }

    protected:
        ngx::memory::pool *pool_;
    };

    /**
     * @namespace main_api
     * @brief 主 API 处理器命名空间
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

        /**
         * @class main_handler
         * @brief 主 API 处理器
         */
        class main_handler final : public handler_base
        {
        public:
            using handler_base::handler_base;

            /**
             * @brief 处理获取商品列表请求
             */
            net::awaitable<void> handle_products(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
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

                    if (!build_json_response(response_data, resp))
                    {
                        build_error_response(ngx::protocol::http::status::internal_server_error, "Internal Server Error", resp);
                        stats.increment_errors();
                        stats.record_status_code(500);
                    }
                    else
                    {
                        resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                        resp.set(ngx::protocol::http::field::cache_control, "public, max-age=60");
                        stats.record_status_code(200);
                    }

                    const auto end_time = std::chrono::steady_clock::now();
                    stats.record_request_time(std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count());
                    stats.record_method("GET");
                }
                catch (...)
                {
                    build_error_response(ngx::protocol::http::status::internal_server_error, "Internal Server Error", resp);
                    stats.increment_errors();
                    stats.record_status_code(500);
                }
                co_return;
            }

            /**
             * @brief 处理获取商品详情请求
             */
            net::awaitable<void> handle_product_detail(std::string_view product_id, ngx::protocol::http::response &resp, detailed_stats &stats)
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
                        if (!build_json_response(target_product, resp))
                        {
                            build_error_response(ngx::protocol::http::status::internal_server_error, "Internal Server Error", resp);
                            stats.increment_errors();
                            stats.record_status_code(500);
                        }
                        else
                        {
                            resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                            stats.record_status_code(200);
                        }
                    }
                    else
                    {
                        build_error_response(ngx::protocol::http::status::not_found, "Not Found", resp);
                        stats.increment_not_found();
                        stats.record_status_code(404);
                    }

                    const auto end_time = std::chrono::steady_clock::now();
                    stats.record_request_time(std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count());
                }
                catch (...)
                {
                    build_error_response(ngx::protocol::http::status::internal_server_error, "Internal Server Error", resp);
                    stats.increment_errors();
                    stats.record_status_code(500);
                }
                co_return;
            }

            /**
             * @brief 处理购物车操作
             */
            net::awaitable<void> handle_cart_operations(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
            {
                stats.increment_api_requests();
                const auto start_time = std::chrono::steady_clock::now();

                const auto method = req.method();
                if (method == ngx::protocol::http::verb::get)
                {
                    const auto cart_data = generate_mock_cart();
                    if (!build_json_response(cart_data, resp))
                    {
                        build_error_response(ngx::protocol::http::status::internal_server_error, "Internal Server Error", resp);
                        stats.record_status_code(500);
                    }
                    else
                    {
                        stats.record_status_code(200);
                    }
                    stats.record_method("GET");
                }
                else if (method == ngx::protocol::http::verb::post)
                {
                    build_constexpr_response(ngx::protocol::http::status::created,
                                             "application/json",
                                             R"({"success":true,"message":"Product added to cart"})",
                                             resp);
                    stats.record_status_code(201);
                    stats.record_method("POST");
                }
                else if (method == ngx::protocol::http::verb::delete_)
                {
                    build_constexpr_response(ngx::protocol::http::status::ok,
                                             "application/json",
                                             R"({"success":true,"message":"Product removed"})",
                                             resp);
                    stats.record_status_code(200);
                    stats.record_method("DELETE");
                }
                else
                {
                    build_constexpr_response(ngx::protocol::http::status::method_not_allowed,
                                             "application/json",
                                             R"({"error":"Method Not Allowed"})",
                                             resp);
                    stats.record_status_code(405);
                }

                const auto end_time = std::chrono::steady_clock::now();
                stats.record_request_time(std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count());
                co_return;
            }

            /**
             * @brief 处理搜索商品请求
             */
            net::awaitable<void> handle_search_products(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
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

                    if (!build_json_response(response_data, resp))
                    {
                        build_error_response(ngx::protocol::http::status::internal_server_error, "Internal Server Error", resp);
                        stats.increment_errors();
                        stats.record_status_code(500);
                    }
                    else
                    {
                        stats.record_status_code(200);
                    }

                    const auto end_time = std::chrono::steady_clock::now();
                    stats.record_request_time(std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count());
                }
                catch (...)
                {
                    build_error_response(ngx::protocol::http::status::internal_server_error, "Internal Server Error", resp);
                    stats.increment_errors();
                    stats.record_status_code(500);
                }
                co_return;
            }

            /**
             * @brief 处理登录请求
             */
            net::awaitable<void> handle_login(ngx::protocol::http::response &resp, detailed_stats &stats)
            {
                stats.increment_api_requests();
                build_constexpr_response(ngx::protocol::http::status::ok,
                                         "application/json",
                                         R"({"success":true,"token":"mock-jwt-token-12345","user":{"id":"user001","name":"用户001"}})",
                                         resp);
                stats.record_status_code(200);
                stats.record_method("POST");
                co_return;
            }

            /**
             * @brief 处理注册请求
             */
            net::awaitable<void> handle_register(ngx::protocol::http::response &resp, detailed_stats &stats)
            {
                stats.increment_api_requests();
                build_constexpr_response(ngx::protocol::http::status::created,
                                         "application/json",
                                         R"({"success":true,"message":"注册成功"})",
                                         resp);
                stats.record_status_code(201);
                stats.record_method("POST");
                co_return;
            }

            /**
             * @brief 处理发送验证码请求
             */
            net::awaitable<void> handle_send_captcha(ngx::protocol::http::response &resp, detailed_stats &stats)
            {
                stats.increment_api_requests();
                build_constexpr_response(ngx::protocol::http::status::ok,
                                         "application/json",
                                         R"({"success":true,"message":"验证码已发送","expire":300})",
                                         resp);
                stats.record_status_code(200);
                stats.record_method("POST");
                co_return;
            }

        private:
            /**
             * @brief 生成模拟商品数据（编译期初始化）
             */
            [[nodiscard]] static std::vector<product> generate_mock_products() noexcept
            {
                return {
                    product{"p001", "高性能无线机械键盘", "采用Cherry MX轴体，支持多设备连接，续航时间长达30天", 599.0, 799.0, "/images/keyboard.jpg", "电子产品", 100, 256, 4.8, {{"品牌", "ForwardEngine"}, {"轴体", "Cherry MX青轴"}, {"连接方式", "蓝牙/2.4G/有线"}}, {{"张三", 5, "手感非常好，打字效率提升明显", "2024-01-15"}, {"李四", 4, "续航很给力，但价格稍贵", "2024-01-10"}}, "采用德国Cherry MX轴体，支持蓝牙5.0、2.4G无线和有线三模连接。"},
                    product{"p002", "4K超高清显示器", "27英寸IPS面板，144Hz刷新率，支持HDR400", 2999.0, 3499.0, "/images/monitor.jpg", "电子产品", 50, 128, 4.9, {{"品牌", "ForwardEngine"}, {"尺寸", "27英寸"}, {"分辨率", "4K"}}, {{"王五", 5, "色彩非常准确，设计工作完美", "2024-01-12"}}, "27英寸IPS面板，4K超高清分辨率，144Hz高刷新率。"},
                    product{"p003", "人体工学办公椅", "网布材质，可调节腰托，支持午休模式", 899.0, 1299.0, "/images/chair.jpg", "家居用品", 80, 200, 4.6, {{"品牌", "ForwardEngine"}, {"材质", "高弹网布"}, {"承重", "150kg"}}, {}, "采用高弹透气网布，4D可调节扶手。"},
                    product{"p004", "智能降噪耳机", "主动降噪，40小时续航，支持多设备同时连接", 1299.0, 1599.0, "/images/headphone.jpg", "电子产品", 120, 512, 4.7, {{"品牌", "ForwardEngine"}, {"降噪等级", "ANC主动降噪"}, {"续航", "40小时"}}, {{"赵六", 5, "降噪效果非常好，通勤必备", "2024-01-08"}}, "采用ANC主动降噪技术，降噪深度可达35dB。"},
                    product{"p005", "便携式SSD硬盘", "1TB容量，Type-C接口，读写速度高达1000MB/s", 699.0, 899.0, "/images/ssd.jpg", "电子产品", 200, 1024, 4.5, {{"品牌", "ForwardEngine"}, {"容量", "1TB"}, {"接口", "USB 3.2 Type-C"}}, {}, "采用NVMe协议，读写速度高达1000MB/s。"},
                };
            }

            /**
             * @brief 生成模拟购物车数据
             */
            [[nodiscard]] static cart_response generate_mock_cart() noexcept
            {
                return cart_response{
                    {cart_item{"p001", "高性能无线机械键盘", 2, 599.0, "/images/keyboard.jpg", 100, "Cherry MX青轴"},
                     cart_item{"p002", "4K超高清显示器", 1, 2999.0, "/images/monitor.jpg", 50, "27英寸"},
                     cart_item{"p004", "智能降噪耳机", 1, 1299.0, "/images/headphone.jpg", 120, "黑色"}},
                    4,
                    5497.0};
            }
        };
    }

    /**
     * @namespace stats_api
     * @brief 统计 API 处理器命名空间
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

        /**
         * @class stats_handler
         * @brief 统计 API 处理器
         */
        class stats_handler final : public handler_base
        {
        public:
            using handler_base::handler_base;

            /**
             * @brief 处理获取统计信息请求
             */
            net::awaitable<void> handle_get_stats(ngx::protocol::http::response &resp, const detailed_stats &stats)
            {
                const auto snapshot = create_snapshot(stats);
                if (!build_json_response(snapshot, resp))
                {
                    build_constexpr_response(ngx::protocol::http::status::internal_server_error,
                                             "application/json",
                                             R"({"error":"Failed to serialize stats"})",
                                             resp);
                }
                else
                {
                    resp.set(ngx::protocol::http::field::cache_control, "no-cache");
                }
                co_return;
            }

            /**
             * @brief 处理获取活动连接请求
             */
            net::awaitable<void> handle_get_active_connections(ngx::protocol::http::response &resp, const detailed_stats &stats)
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
                if (!build_json_response(response_data, resp))
                {
                    build_constexpr_response(ngx::protocol::http::status::internal_server_error,
                                             "application/json",
                                             R"({"error":"Failed to serialize connections"})",
                                             resp);
                }
                co_return;
            }

            /**
             * @brief 处理获取流量历史请求
             */
            net::awaitable<void> handle_get_traffic_history(ngx::protocol::http::response &resp, const detailed_stats &stats, std::uint32_t minutes)
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

                if (!build_json_response(history_response, resp))
                {
                    build_constexpr_response(ngx::protocol::http::status::internal_server_error,
                                             "application/json",
                                             R"({"error":"Failed to serialize traffic history"})",
                                             resp);
                }
                co_return;
            }

            /**
             * @brief 处理获取性能指标请求
             */
            net::awaitable<void> handle_get_performance(ngx::protocol::http::response &resp, const detailed_stats &stats)
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

                if (!build_json_response(metrics, resp))
                {
                    build_constexpr_response(ngx::protocol::http::status::internal_server_error,
                                             "application/json",
                                             R"({"error":"Failed to serialize performance metrics"})",
                                             resp);
                }
                co_return;
            }
        };
    }

    // 使用工厂函数创建处理器（避免直接暴露构造函数）
    [[nodiscard]] inline std::unique_ptr<main_api::main_handler> create_main_handler(ngx::memory::pool *pool) noexcept
    {
        return std::make_unique<main_api::main_handler>(pool);
    }

    [[nodiscard]] inline std::unique_ptr<stats_api::stats_handler> create_stats_handler(ngx::memory::pool *pool) noexcept
    {
        return std::make_unique<stats_api::stats_handler>(pool);
    }
}

// glaze JSON 序列化模板特化（与原始 processor.hpp 保持一致）
template <>
struct glz::meta<srv::handler::main_api::product>
{
    using T = srv::handler::main_api::product;
    static constexpr auto value = glz::object(
        "id", &T::id, "name", &T::name, "description", &T::description,
        "price", &T::price, "original_price", &T::original_price, "image", &T::image,
        "category", &T::category, "stock", &T::stock, "sales", &T::sales,
        "rating", &T::rating, "specs", &T::specs, "reviews", &T::reviews, "detail", &T::detail);
};

template <>
struct glz::meta<srv::handler::main_api::product_spec>
{
    using T = srv::handler::main_api::product_spec;
    static constexpr auto value = glz::object("name", &T::name, "value", &T::value);
};

template <>
struct glz::meta<srv::handler::main_api::product_review>
{
    using T = srv::handler::main_api::product_review;
    static constexpr auto value = glz::object(
        "author", &T::author,
        "rating", &T::rating,
        "content", &T::content,
        "date", &T::date);
};

template <>
struct glz::meta<srv::handler::main_api::products_response>
{
    using T = srv::handler::main_api::products_response;
    static constexpr auto value = glz::object("items", &T::items, "total", &T::total, "page", &T::page, "page_size", &T::page_size);
};

template <>
struct glz::meta<srv::handler::main_api::cart_item>
{
    using T = srv::handler::main_api::cart_item;
    static constexpr auto value = glz::object("id", &T::id, "name", &T::name, "quantity", &T::quantity, "price", &T::price, "image", &T::image, "stock", &T::stock, "spec", &T::spec);
};

template <>
struct glz::meta<srv::handler::main_api::cart_response>
{
    using T = srv::handler::main_api::cart_response;
    static constexpr auto value = glz::object("items", &T::items, "total_items", &T::total_items, "total_price", &T::total_price);
};

template <>
struct glz::meta<srv::handler::main_api::search_response>
{
    using T = srv::handler::main_api::search_response;
    static constexpr auto value = glz::object("results", &T::results, "total", &T::total, "query", &T::query);
};

template <>
struct glz::meta<srv::handler::stats_api::traffic_history>
{
    using T = srv::handler::stats_api::traffic_history;
    static constexpr auto value = glz::object("timestamp", &T::timestamp, "bytes_sent", &T::bytes_sent, "bytes_received", &T::bytes_received);
};

template <>
struct glz::meta<srv::handler::stats_api::connections_response>
{
    using T = srv::handler::stats_api::connections_response;
    static constexpr auto value = glz::object("connections", &T::connections);
};

template <>
struct glz::meta<srv::handler::stats_api::traffic_history_response>
{
    using T = srv::handler::stats_api::traffic_history_response;
    static constexpr auto value = glz::object("history", &T::history, "interval_seconds", &T::interval_seconds);
};

template <>
struct glz::meta<srv::handler::stats_api::performance_metrics>
{
    using T = srv::handler::stats_api::performance_metrics;
    static constexpr auto value = glz::object("cpu_usage_percent", &T::cpu_usage_percent, "memory_usage_mb", &T::memory_usage_mb, "active_threads", &T::active_threads, "io_wait_percent", &T::io_wait_percent);
};