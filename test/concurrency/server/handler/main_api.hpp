/**
 * @file main_api.hpp
 * @brief 主 API 处理器定义
 * @details 处理主端口的 API 请求，包括商品列表、商品详情、购物车操作、商品搜索等。
 *
 * 核心特性：
 * - 商品管理：支持商品列表、商品详情、商品搜索
 * - 购物车操作：支持获取、添加、删除购物车商品
 * - JSON 序列化：使用 glaze 库进行 JSON 序列化
 * - 统计记录：记录请求时间、状态码、方法等统计信息
 *
 * @note 设计原则：
 * - 模拟数据：使用模拟数据进行测试和演示
 * - 异步处理：使用协程风格异步处理请求
 * - 错误处理：完善的异常处理和错误响应
 *
 */
#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <chrono>
#include <algorithm>
#include <cctype>

#include "../stats/metrics.hpp"
#include "../mime/types.hpp"
#include <forward-engine/protocol/http/request.hpp>
#include <forward-engine/protocol/http/response.hpp>
#include <forward-engine/protocol/http/constants.hpp>
#include <forward-engine/transformer/json.hpp>
#include <glaze/glaze.hpp>
#include <boost/asio.hpp>

namespace srv::handler::main_api
{
    using namespace srv::stats;
    using namespace srv::mime;
    using namespace ngx::transformer::json;

    struct product final
    {
        std::string id;
        std::string name;
        std::string description;
        double price;
        double original_price;
        std::string image;
        std::string category;
        std::uint32_t stock;
        std::uint32_t sales;
        double rating;
    };

    struct products_response final
    {
        std::vector<product> items;
        std::uint32_t total;
        std::uint32_t page;
        std::uint32_t page_size;
    };

    struct cart_item final
    {
        std::string product_id;
        std::string product_name;
        std::uint32_t quantity;
        double price;
        std::string image;
    };

    struct cart_response final
    {
        std::vector<cart_item> items;
        std::uint32_t total_items;
        double total_price;
    };

    struct search_response final
    {
        std::vector<product> results;
        std::uint32_t total;
        std::string query;
    };

    [[nodiscard]] inline std::vector<product> generate_mock_products() noexcept
    {
        return {
            product{"p001", "高性能无线机械键盘", "采用Cherry MX轴体，支持多设备连接，续航时间长达30天", 599.0, 799.0, "/images/keyboard.jpg", "电子产品", 100, 256, 4.8},
            product{"p002", "4K超高清显示器", "27英寸IPS面板，144Hz刷新率，支持HDR400", 2999.0, 3499.0, "/images/monitor.jpg", "电子产品", 50, 128, 4.9},
            product{"p003", "人体工学办公椅", "网布材质，可调节腰托，支持午休模式", 899.0, 1299.0, "/images/chair.jpg", "家居用品", 80, 200, 4.6},
            product{"p004", "智能降噪耳机", "主动降噪，40小时续航，支持多设备同时连接", 1299.0, 1599.0, "/images/headphone.jpg", "电子产品", 120, 512, 4.7},
            product{"p005", "便携式SSD硬盘", "1TB容量，Type-C接口，读写速度高达1000MB/s", 699.0, 899.0, "/images/ssd.jpg", "电子产品", 200, 1024, 4.5},
            product{"p006", "游戏鼠标", "16000DPI光学传感器，RGB灯效，支持无线充电", 399.0, 499.0, "/images/mouse.jpg", "电子产品", 150, 768, 4.4},
            product{"p007", "机械手表", "自动上链机芯，蓝宝石玻璃镜面，50米防水", 5999.0, 6999.0, "/images/watch.jpg", "服饰配饰", 30, 64, 4.9},
            product{"p008", "运动跑鞋", "透气网面，缓震中底，适合日常跑步训练", 599.0, 799.0, "/images/shoes.jpg", "服饰配饰", 180, 384, 4.3},
            product{"p009", "智能音箱", "支持语音控制，高品质音效，智能家居中枢", 499.0, 699.0, "/images/speaker.jpg", "智能家居", 250, 896, 4.6},
            product{"p010", "空气净化器", "HEPA过滤，除甲醛，适用面积60平米", 1299.0, 1599.0, "/images/purifier.jpg", "家居用品", 90, 192, 4.5},
            product{"p011", "电动牙刷", "声波震动，5种清洁模式，无线充电底座", 299.0, 399.0, "/images/toothbrush.jpg", "个人护理", 300, 2048, 4.4},
            product{"p012", "平板电脑", "10.9英寸视网膜屏，支持手写笔，256GB存储", 3999.0, 4499.0, "/images/tablet.jpg", "电子产品", 60, 320, 4.8},
            product{"p013", "咖啡机", "意式浓缩，15Bar压力，支持咖啡豆和胶囊", 1599.0, 1999.0, "/images/coffee.jpg", "家用电器", 45, 128, 4.7},
            product{"p014", "户外帐篷", "防水防风，3-4人适用，快速搭建", 499.0, 699.0, "/images/tent.jpg", "户外用品", 70, 192, 4.5},
            product{"p015", "无人机", "4K航拍，30分钟续航，智能避障", 3999.0, 4999.0, "/images/drone.jpg", "电子产品", 25, 64, 4.6}};
    }

    [[nodiscard]] inline cart_response generate_mock_cart() noexcept
    {
        return cart_response{
            {cart_item{"p001", "高性能无线机械键盘", 2, 599.0, "/images/keyboard.jpg"},
             cart_item{"p002", "4K超高清显示器", 1, 2999.0, "/images/monitor.jpg"},
             cart_item{"p004", "智能降噪耳机", 1, 1299.0, "/images/headphone.jpg"}},
            4,
            5497.0};
    }

    inline boost::asio::awaitable<void> get_products(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
    {
        stats.increment_requests();
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

                auto it = query_string.begin();
                while (it != query_string.end())
                {
                    auto param_end = std::find(it, query_string.end(), '&');
                    std::string_view param(it, param_end);

                    auto eq_pos = param.find('=');
                    if (eq_pos != std::string_view::npos)
                    {
                        const auto key = param.substr(0, eq_pos);
                        const auto value = param.substr(eq_pos + 1);

                        if (key == "page")
                        {
                            page = static_cast<std::uint32_t>(std::stoi(std::string(value)));
                        }
                        else if (key == "page_size")
                        {
                            page_size = static_cast<std::uint32_t>(std::stoi(std::string(value)));
                        }
                        else if (key == "category")
                        {
                            category_filter = value;
                        }
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
                    {
                        filtered_products.push_back(prod);
                    }
                }
            }

            const std::uint32_t total = static_cast<std::uint32_t>(filtered_products.size());

            const std::uint32_t start_index = (page - 1) * page_size;
            const std::uint32_t end_index = std::min(start_index + page_size, total);

            std::vector<product> page_products;
            if (start_index < total)
            {
                for (std::uint32_t i = start_index; i < end_index; ++i)
                {
                    page_products.push_back(filtered_products[i]);
                }
            }

            products_response response_data{std::move(page_products), total, page, page_size};

            auto json_buffer = serialize(response_data);

            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
            resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
            resp.set(ngx::protocol::http::field::cache_control, "public, max-age=60");
            resp.body(std::string(json_buffer));

            const auto end_time = std::chrono::steady_clock::now();
            const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
            stats.record_request_time(duration_ns);
            stats.record_status_code(200);
            stats.record_method("GET");
        }
        catch (...)
        {
            resp.status(ngx::protocol::http::status::internal_server_error);
            resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
            resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
            resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to retrieve products"})"));
            stats.increment_errors();
            stats.record_status_code(500);
        }

        co_return;
    }

    inline boost::asio::awaitable<void> get_product_detail([[maybe_unused]] ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats,
                                                           std::string_view product_id)
    {
        stats.increment_requests();
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
                resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.set(ngx::protocol::http::field::cache_control, "public, max-age=300");
                resp.body(std::string(json_buffer));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(200);
                stats.record_method("GET");
            }
            else
            {
                resp.status(ngx::protocol::http::status::not_found);
                resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Not Found","message":"Product not found"})"));
                stats.increment_not_found();
                stats.record_status_code(404);
            }
        }
        catch (...)
        {
            resp.status(ngx::protocol::http::status::internal_server_error);
            resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
            resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
            resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to retrieve product detail"})"));
            stats.increment_errors();
            stats.record_status_code(500);
        }

        co_return;
    }

    inline boost::asio::awaitable<void> cart_operations(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
    {
        stats.increment_requests();
        stats.increment_api_requests();

        const auto start_time = std::chrono::steady_clock::now();

        try
        {
            const auto method = req.method();

            if (method == ngx::protocol::http::verb::get)
            {
                const auto cart_data = generate_mock_cart();

                auto json_buffer = serialize(cart_data);

                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string(json_buffer));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(200);
                stats.record_method("GET");
            }
            else if (method == ngx::protocol::http::verb::post)
            {
                resp.status(ngx::protocol::http::status::created);
                resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"success":true,"message":"Product added to cart"})"));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(201);
                stats.record_method("POST");
            }
            else if (method == ngx::protocol::http::verb::delete_)
            {
                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"success":true,"message":"Product removed from cart"})"));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(200);
                stats.record_method("DELETE");
            }
            else
            {
                resp.status(ngx::protocol::http::status::method_not_allowed);
                resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Method Not Allowed","message":"HTTP method not supported for this endpoint"})"));
                stats.record_status_code(405);
            }
        }
        catch (...)
        {
            resp.status(ngx::protocol::http::status::internal_server_error);
            resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
            resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
            resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to process cart operation"})"));
            stats.increment_errors();
            stats.record_status_code(500);
        }

        co_return;
    }

    inline boost::asio::awaitable<void> search_products(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
    {
        stats.increment_requests();
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

                auto q_pos = query_string.find("q=");
                if (q_pos != std::string_view::npos)
                {
                    auto q_value_start = q_pos + 2;
                    auto q_value_end = query_string.find('&', q_value_start);

                    if (q_value_end == std::string_view::npos)
                    {
                        search_query = std::string(query_string.substr(q_value_start));
                    }
                    else
                    {
                        search_query = std::string(query_string.substr(q_value_start, q_value_end - q_value_start));
                    }
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
                std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(), [](unsigned char c)
                               { return static_cast<char>(std::tolower(c)); });

                for (const auto &prod : all_products)
                {
                    std::string lower_name = prod.name;
                    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), [](unsigned char c)
                                   { return static_cast<char>(std::tolower(c)); });

                    std::string lower_desc = prod.description;
                    std::transform(lower_desc.begin(), lower_desc.end(), lower_desc.begin(), [](unsigned char c)
                                   { return static_cast<char>(std::tolower(c)); });

                    std::string lower_category = prod.category;
                    std::transform(lower_category.begin(), lower_category.end(), lower_category.begin(), [](unsigned char c)
                                   { return static_cast<char>(std::tolower(c)); });

                    if (lower_name.find(lower_query) != std::string::npos ||
                        lower_desc.find(lower_query) != std::string::npos ||
                        lower_category.find(lower_query) != std::string::npos)
                    {
                        search_results.push_back(prod);
                    }
                }
            }

            search_response response_data{std::move(search_results), static_cast<std::uint32_t>(search_results.size()), search_query};

            auto json_buffer = serialize(response_data);

            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
            resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
            resp.set(ngx::protocol::http::field::cache_control, "public, max-age=60");
            resp.body(std::string(json_buffer));

            const auto end_time = std::chrono::steady_clock::now();
            const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
            stats.record_request_time(duration_ns);
            stats.record_status_code(200);
            stats.record_method("GET");
        }
        catch (...)
        {
            resp.status(ngx::protocol::http::status::internal_server_error);
            resp.set(ngx::protocol::http::field::content_type, JSON_CONTENT_TYPE);
            resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
            resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to search products"})"));
            stats.increment_errors();
            stats.record_status_code(500);
        }

        co_return;
    }
}

template <>
struct glz::meta<srv::handler::main_api::product>
{
    using T = srv::handler::main_api::product;
    static constexpr auto value = glz::object(
        "id", &T::id,
        "name", &T::name,
        "description", &T::description,
        "price", &T::price,
        "original_price", &T::original_price,
        "image", &T::image,
        "category", &T::category,
        "stock", &T::stock,
        "sales", &T::sales,
        "rating", &T::rating);
};

template <>
struct glz::meta<srv::handler::main_api::products_response>
{
    using T = srv::handler::main_api::products_response;
    static constexpr auto value = glz::object(
        "items", &T::items,
        "total", &T::total,
        "page", &T::page,
        "page_size", &T::page_size);
};

template <>
struct glz::meta<srv::handler::main_api::cart_item>
{
    using T = srv::handler::main_api::cart_item;
    static constexpr auto value = glz::object(
        "product_id", &T::product_id,
        "product_name", &T::product_name,
        "quantity", &T::quantity,
        "price", &T::price,
        "image", &T::image);
};

template <>
struct glz::meta<srv::handler::main_api::cart_response>
{
    using T = srv::handler::main_api::cart_response;
    static constexpr auto value = glz::object(
        "items", &T::items,
        "total_items", &T::total_items,
        "total_price", &T::total_price);
};

template <>
struct glz::meta<srv::handler::main_api::search_response>
{
    using T = srv::handler::main_api::search_response;
    static constexpr auto value = glz::object(
        "results", &T::results,
        "total", &T::total,
        "query", &T::query);
};
