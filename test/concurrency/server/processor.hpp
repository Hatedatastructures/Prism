/**
 * @file processor.hpp
 * @brief 请求处理器模块
 * @details 提供静态文件服务、主 API 和统计 API 的请求处理功能。
 *
 * 核心特性：
 * - 静态文件服务：支持路径安全验证、MIME 类型检测、缓存控制
 * - 主 API：商品列表、商品详情、购物车操作、商品搜索
 * - 统计 API：统计快照、活动连接、流量历史、性能指标
 * - JSON 序列化：使用封装的 serialize 函数
 *
 * @note 设计原则：
 * - 安全优先：严格验证文件路径
 * - 异步处理：使用协程风格异步处理请求
 * - 错误处理：完善的异常处理和错误响应
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

#ifdef _WIN32
#include <windows.h>
#endif

#include "statistics.hpp"
#include "mime.hpp"
#include <forward-engine/protocol/http/request.hpp>
#include <forward-engine/protocol/http/response.hpp>
#include <forward-engine/protocol/http/constants.hpp>
#include <forward-engine/transformer/json.hpp>
#include <glaze/glaze.hpp>
#include <boost/asio.hpp>

namespace srv::processor
{
    namespace fs = std::filesystem;
    using namespace srv::statistics;
    using namespace ngx::transformer::json;

    /**
     * @brief 安全的字符串转整数函数
     * @tparam IntType 整数类型
     * @param str 输入字符串
     * @param default_value 解析失败时的默认值
     * @return 解析结果或默认值
     * @note 不会抛出异常，使用 std::from_chars 进行安全解析
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
     * @details 负责处理静态文件请求，包括路径解析、安全验证、文件读取和 HTTP 响应构建
     */
    class static_handler final
    {
    public:
        static_handler() = default;

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

            if (!fs::exists(full_path) || !fs::is_regular_file(full_path))
            {
                stats.increment_not_found();
                return false;
            }

            const auto file_size = fs::file_size(full_path);
            if (file_size > static_cast<std::uintmax_t>(MAX_FILE_SIZE))
            {
                return false;
            }

            try
            {
                std::ifstream file(full_path, std::ios::binary);
                if (!file.is_open())
                {
                    return false;
                }

                std::string body;
                body.resize(static_cast<std::size_t>(file_size));
                file.read(body.data(), static_cast<std::streamsize>(file_size));

                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, srv::mime::obtain_mapping(path));
                resp.set(ngx::protocol::http::field::content_length, std::to_string(file_size));
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

        [[nodiscard]] static std::string resolve_path(std::string_view path)
        {
            std::string result(path);

            if (result.empty() || result == "/")
            {
                result = "/index.html";
            }

            if (result.find("..") != std::string::npos)
            {
                return "/index.html";
            }

            const std::string base_dir = "webroot";
            if (result[0] == '/')
            {
                result = base_dir + result;
            }
            else
            {
                result = base_dir + "/" + result;
            }

            return result;
        }

        [[nodiscard]] static bool validate_path(const std::string &path)
        {
            const std::string base_dir = fs::absolute("webroot").string();
            const std::string full_path = fs::absolute(path).string();

            if (full_path.find(base_dir) != 0)
            {
                return false;
            }

            return true;
        }

        [[nodiscard]] static std::string get_last_modified(const std::string &path)
        {
            const auto ftime = fs::last_write_time(path);
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
            const auto ftime = fs::last_write_time(path);
            const auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
            const auto c_time = std::chrono::system_clock::to_time_t(sctp);

            return std::format("\"{:x}-{:x}\"", static_cast<unsigned long>(c_time), static_cast<unsigned long long>(size));
        }
    };

    /**
     * @namespace main_api
     * @brief 主 API 命名空间
     * @details 提供主端点的 API 处理功能，包括商品、购物车、搜索等接口
     */
    namespace main_api
    {
        /**
         * @struct product_spec
         * @brief 商品规格结构体
         * @details 存储商品的规格参数，如品牌、型号、颜色等
         */
        struct product_spec final
        {
            /// @brief 规格名称
            std::string name;
            /// @brief 规格值
            std::string value;
        };

        /**
         * @struct product_review
         * @brief 商品评价结构体
         * @details 存储用户对商品的评价信息
         */
        struct product_review final
        {
            /// @brief 评价作者
            std::string author;
            /// @brief 评分（1-5）
            std::uint32_t rating{0};
            /// @brief 评价内容
            std::string content;
            /// @brief 评价日期
            std::string date;
        };

        /**
         * @struct product
         * @brief 商品结构体
         * @details 存储商品的完整信息，包括基本信息、规格、评价等
         */
        struct product final
        {
            /// @brief 商品 ID
            std::string id;
            /// @brief 商品名称
            std::string name;
            /// @brief 商品描述
            std::string description;
            /// @brief 当前价格
            double price{0.0};
            /// @brief 原价
            double original_price{0.0};
            /// @brief 商品图片 URL
            std::string image;
            /// @brief 商品分类
            std::string category;
            /// @brief 库存数量
            std::uint32_t stock{0};
            /// @brief 销量
            std::uint32_t sales{0};
            /// @brief 评分
            double rating{0.0};
            /// @brief 规格列表
            std::vector<product_spec> specs;
            /// @brief 评价列表
            std::vector<product_review> reviews;
            /// @brief 商品详情描述
            std::string detail;
        };

        /**
         * @struct products_response
         * @brief 商品列表响应结构体
         * @details 存储商品列表 API 的响应数据，支持分页
         */
        struct products_response final
        {
            /// @brief 商品列表
            std::vector<product> items;
            /// @brief 商品总数
            std::uint32_t total{0};
            /// @brief 当前页码
            std::uint32_t page{1};
            /// @brief 每页数量
            std::uint32_t page_size{10};
        };

        /**
         * @struct cart_item
         * @brief 购物车商品结构体
         * @details 存储购物车中的商品信息
         */
        struct cart_item final
        {
            /// @brief 商品 ID
            std::string id;
            /// @brief 商品名称
            std::string name;
            /// @brief 购买数量
            std::uint32_t quantity{0};
            /// @brief 单价
            double price{0.0};
            /// @brief 商品图片 URL
            std::string image;
            /// @brief 库存数量
            std::uint32_t stock{0};
            /// @brief 规格描述
            std::string spec;
        };

        /**
         * @struct cart_response
         * @brief 购物车响应结构体
         * @details 存储购物车 API 的响应数据
         */
        struct cart_response final
        {
            /// @brief 购物车商品列表
            std::vector<cart_item> items;
            /// @brief 商品总数量
            std::uint32_t total_items{0};
            /// @brief 总价
            double total_price{0.0};
        };

        /**
         * @struct search_response
         * @brief 搜索响应结构体
         * @details 存储商品搜索 API 的响应数据
         */
        struct search_response final
        {
            /// @brief 搜索结果列表
            std::vector<product> results;
            /// @brief 结果总数
            std::uint32_t total{0};
            /// @brief 搜索关键词
            std::string query;
        };

        /**
         * @brief 生成模拟商品数据
         * @return 商品列表
         */
        [[nodiscard]] inline std::vector<product> generate_mock_products() noexcept
        {
            return {
                product{"p001", "高性能无线机械键盘", "采用Cherry MX轴体，支持多设备连接，续航时间长达30天", 599.0, 799.0, "/images/keyboard.jpg", "电子产品", 100, 256, 4.8, {{"品牌", "ForwardEngine"}, {"轴体", "Cherry MX青轴"}, {"连接方式", "蓝牙/2.4G/有线"}}, {{"张三", 5, "手感非常好，打字效率提升明显", "2024-01-15"}, {"李四", 4, "续航很给力，但价格稍贵", "2024-01-10"}}, "采用德国Cherry MX轴体，支持蓝牙5.0、2.4G无线和有线三模连接。内置4000mAh大容量电池，续航时间长达30天。铝合金外壳，PBT键帽，支持全键无冲。"},
                product{"p002", "4K超高清显示器", "27英寸IPS面板，144Hz刷新率，支持HDR400", 2999.0, 3499.0, "/images/monitor.jpg", "电子产品", 50, 128, 4.9, {{"品牌", "ForwardEngine"}, {"尺寸", "27英寸"}, {"分辨率", "4K (3840x2160)"}, {"刷新率", "144Hz"}}, {{"王五", 5, "色彩非常准确，设计工作完美", "2024-01-12"}}, "27英寸IPS面板，4K超高清分辨率，144Hz高刷新率。支持HDR400，99% sRGB色域覆盖。Type-C一线通连接，支持90W反向充电。"},
                product{"p003", "人体工学办公椅", "网布材质，可调节腰托，支持午休模式", 899.0, 1299.0, "/images/chair.jpg", "家居用品", 80, 200, 4.6, {{"品牌", "ForwardEngine"}, {"材质", "高弹网布"}, {"承重", "150kg"}}, {}, "采用高弹透气网布，4D可调节扶手，可调节腰托和头枕。座椅可135度后仰，支持午休模式。五星脚轮，静音滑动。"},
                product{"p004", "智能降噪耳机", "主动降噪，40小时续航，支持多设备同时连接", 1299.0, 1599.0, "/images/headphone.jpg", "电子产品", 120, 512, 4.7, {{"品牌", "ForwardEngine"}, {"降噪等级", "ANC主动降噪"}, {"续航", "40小时"}}, {{"赵六", 5, "降噪效果非常好，通勤必备", "2024-01-08"}}, "采用ANC主动降噪技术，降噪深度可达35dB。40mm大尺寸动圈单元，支持LDAC高清音频编解码。40小时超长续航，支持快充。"},
                product{"p005", "便携式SSD硬盘", "1TB容量，Type-C接口，读写速度高达1000MB/s", 699.0, 899.0, "/images/ssd.jpg", "电子产品", 200, 1024, 4.5, {{"品牌", "ForwardEngine"}, {"容量", "1TB"}, {"接口", "USB 3.2 Type-C"}}, {}, "采用NVMe协议，读写速度高达1000MB/s。Type-C接口，兼容Windows/Mac/Linux。金属外壳，支持密码加密。"},
                product{"p006", "游戏鼠标", "16000DPI光学传感器，RGB灯效，支持无线充电", 399.0, 499.0, "/images/mouse.jpg", "电子产品", 150, 768, 4.4, {{"品牌", "ForwardEngine"}, {"DPI", "16000"}, {"按键数", "8键"}}, {}, "采用PMW3389光学传感器，16000DPI精准追踪。8个可编程按键，RGB灯效可自定义。支持Qi无线充电。"},
                product{"p007", "机械手表", "自动上链机芯，蓝宝石玻璃镜面，50米防水", 5999.0, 6999.0, "/images/watch.jpg", "服饰配饰", 30, 64, 4.9, {{"品牌", "ForwardEngine"}, {"机芯", "自动上链机械机芯"}, {"防水", "50米"}}, {{"钱七", 5, "做工精致，戴着很有气质", "2024-01-05"}}, "采用瑞士自动上链机械机芯，蓝宝石玻璃镜面。316L不锈钢表壳，50米防水。透明底盖可见机芯运转。"},
                product{"p008", "运动跑鞋", "透气网面，缓震中底，适合日常跑步训练", 599.0, 799.0, "/images/shoes.jpg", "服饰配饰", 180, 384, 4.3, {{"品牌", "ForwardEngine"}, {"适用场景", "跑步/训练"}, {"鞋面", "透气网面"}}, {}, "采用Flyknit透气网面鞋面，轻盈舒适。全掌Zoom气垫缓震，橡胶大底防耐磨。适合日常跑步训练。"},
                product{"p009", "智能音箱", "支持语音控制，高品质音效，智能家居中枢", 499.0, 699.0, "/images/speaker.jpg", "智能家居", 250, 896, 4.6, {{"品牌", "ForwardEngine"}, {"语音助手", "小爱同学"}, {"扬声器", "2.0声道"}}, {}, "支持小爱同学语音助手，可控制智能家居设备。2.0声道设计，支持蓝牙5.0和WiFi连接。"},
                product{"p010", "空气净化器", "HEPA过滤，除甲醛，适用面积60平米", 1299.0, 1599.0, "/images/purifier.jpg", "家居用品", 90, 192, 4.5, {{"品牌", "ForwardEngine"}, {"过滤等级", "H13 HEPA"}, {"适用面积", "60平米"}}, {}, "采用H13级HEPA滤网，过滤99.97%的PM2.5颗粒。活性炭滤层有效去除甲醛和异味。CADR值500立方米/小时。"},
                product{"p011", "电动牙刷", "声波震动，5种清洁模式，无线充电底座", 299.0, 399.0, "/images/toothbrush.jpg", "个人护理", 300, 2048, 4.4, {{"品牌", "ForwardEngine"}, {"震动频率", "40000次/分钟"}, {"续航", "30天"}}, {}, "声波震动技术，每分钟40000次高频震动。5种清洁模式，满足不同需求。无线充电底座，30天超长续航。"},
                product{"p012", "平板电脑", "10.9英寸视网膜屏，支持手写笔，256GB存储", 3999.0, 4499.0, "/images/tablet.jpg", "电子产品", 60, 320, 4.8, {{"品牌", "ForwardEngine"}, {"屏幕", "10.9英寸视网膜屏"}, {"存储", "256GB"}}, {{"孙八", 5, "屏幕非常清晰，生产力工具", "2024-01-02"}}, "10.9英寸Liquid视网膜显示屏，P3广色域。A14仿生芯片，256GB存储。支持第二代手写笔和妙控键盘。"},
                product{"p013", "咖啡机", "意式浓缩，15Bar压力，支持咖啡豆和胶囊", 1599.0, 1999.0, "/images/coffee.jpg", "家用电器", 45, 128, 4.7, {{"品牌", "ForwardEngine"}, {"压力", "15Bar"}, {"水箱容量", "1.5L"}}, {}, "15Bar意大利泵，专业意式浓缩。支持咖啡豆和胶囊两种模式。不锈钢机身，1.5L可拆卸水箱。"},
                product{"p014", "户外帐篷", "防水防风，3-4人适用，快速搭建", 499.0, 699.0, "/images/tent.jpg", "户外用品", 70, 192, 4.5, {{"品牌", "ForwardEngine"}, {"容纳人数", "3-4人"}, {"防水等级", "3000mm"}}, {}, "采用210T涤纶防水面料，防水等级3000mm。铝合金支架，抗风性强。3分钟快速搭建，附带地钉和风绳。"},
                product{"p015", "无人机", "4K航拍，30分钟续航，智能避障", 3999.0, 4999.0, "/images/drone.jpg", "电子产品", 25, 64, 4.6, {{"品牌", "ForwardEngine"}, {"摄像头", "4K/60fps"}, {"续航", "30分钟"}}, {{"周九", 5, "画质非常棒，避障很智能", "2024-01-01"}}, "1/2英寸CMOS传感器，支持4K/60fps视频拍摄。三向智能避障系统，30分钟超长续航。支持GPS和视觉定位。"},
            };
        }

        /**
         * @brief 生成模拟购物车数据
         * @return 购物车响应数据
         */
        [[nodiscard]] inline cart_response generate_mock_cart() noexcept
        {
            return cart_response{
                {cart_item{"p001", "高性能无线机械键盘", 2, 599.0, "/images/keyboard.jpg", 100, "Cherry MX青轴"},
                 cart_item{"p002", "4K超高清显示器", 1, 2999.0, "/images/monitor.jpg", 50, "27英寸"},
                 cart_item{"p004", "智能降噪耳机", 1, 1299.0, "/images/headphone.jpg", 120, "黑色"}},
                4,
                5497.0};
        }

        /**
         * @brief 获取商品列表 API
         * @param req HTTP 请求
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> get_products(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
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
                                page = safe_parse_int<std::uint32_t>(value, 1);
                            }
                            else if (key == "page_size")
                            {
                                page_size = safe_parse_int<std::uint32_t>(value, 10);
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
                resp.set(ngx::protocol::http::field::content_type, "application/json");
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
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to retrieve products"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 获取商品详情 API
         * @param req HTTP 请求
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @param product_id 商品 ID
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> get_product_detail([[maybe_unused]] ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats,
                                                               std::string_view product_id)
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
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string_view(R"({"error":"Not Found","message":"Product not found"})"));
                    stats.increment_not_found();
                    stats.record_status_code(404);
                }
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to retrieve product detail"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 购物车操作 API（GET 获取、POST 添加、DELETE 删除）
         * @param req HTTP 请求
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> cart_operations(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
        {
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
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
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
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
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
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
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
                    resp.set(ngx::protocol::http::field::content_type, "application/json");
                    resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                    resp.body(std::string_view(R"({"error":"Method Not Allowed","message":"HTTP method not supported for this endpoint"})"));
                    stats.record_status_code(405);
                }
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to process cart operation"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 更新购物车商品 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> update_cart_item(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();

            const auto start_time = std::chrono::steady_clock::now();

            try
            {
                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"success":true,"message":"Cart item updated"})"));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(200);
                stats.record_method("PUT");
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to update cart item"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 删除购物车商品 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> delete_cart_item(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();

            const auto start_time = std::chrono::steady_clock::now();

            try
            {
                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"success":true,"message":"Cart item deleted"})"));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(200);
                stats.record_method("DELETE");
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to delete cart item"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 批量删除购物车商品 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> delete_cart_items(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();

            const auto start_time = std::chrono::steady_clock::now();

            try
            {
                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"success":true,"message":"Cart items deleted"})"));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(200);
                stats.record_method("DELETE");
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to delete cart items"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 购物车结算 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> cart_checkout(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();

            const auto start_time = std::chrono::steady_clock::now();

            try
            {
                const auto cart_data = generate_mock_cart();

                auto json_buffer = serialize(cart_data);

                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string(json_buffer));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(200);
                stats.record_method("POST");
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to process checkout"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 创建订单 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> create_order(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();

            const auto start_time = std::chrono::steady_clock::now();

            try
            {
                resp.status(ngx::protocol::http::status::created);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"success":true,"order_id":"ORD-20240101-001","message":"Order created successfully"})"));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(201);
                stats.record_method("POST");
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to create order"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 搜索商品 API
         * @param req HTTP 请求
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> search_products(ngx::protocol::http::request &req, ngx::protocol::http::response &resp, detailed_stats &stats)
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

                    // 支持 search= 和 q= 两种参数名
                    auto search_pos = query_string.find("search=");
                    auto q_pos = query_string.find("q=");
                    auto param_pos = std::string_view::npos;

                    if (search_pos != std::string_view::npos)
                    {
                        param_pos = search_pos + 7; // "search=".length()
                    }
                    else if (q_pos != std::string_view::npos)
                    {
                        param_pos = q_pos + 2; // "q=".length()
                    }

                    if (param_pos != std::string_view::npos)
                    {
                        auto value_end = query_string.find('&', param_pos);

                        if (value_end == std::string_view::npos)
                        {
                            search_query = std::string(query_string.substr(param_pos));
                        }
                        else
                        {
                            search_query = std::string(query_string.substr(param_pos, value_end - param_pos));
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
                resp.set(ngx::protocol::http::field::content_type, "application/json");
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
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to search products"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 用户登录 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> login(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();

            const auto start_time = std::chrono::steady_clock::now();

            try
            {
                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"success":true,"token":"mock-jwt-token-12345","user":{"id":"user001","name":"用户001","email":"user@example.com","avatar":"/images/avatar.jpg"}})"));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(200);
                stats.record_method("POST");
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to login"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 用户注册 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> register_user(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();

            const auto start_time = std::chrono::steady_clock::now();

            try
            {
                resp.status(ngx::protocol::http::status::created);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"success":true,"message":"注册成功","user":{"id":"user002","name":"新用户","email":"newuser@example.com"}})"));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(201);
                stats.record_method("POST");
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to register"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }

        /**
         * @brief 发送验证码 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline boost::asio::awaitable<void> send_captcha(ngx::protocol::http::response &resp, detailed_stats &stats)
        {
            stats.increment_api_requests();

            const auto start_time = std::chrono::steady_clock::now();

            try
            {
                resp.status(ngx::protocol::http::status::ok);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"success":true,"message":"验证码已发送","expire":300})"));

                const auto end_time = std::chrono::steady_clock::now();
                const auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time).count();
                stats.record_request_time(duration_ns);
                stats.record_status_code(200);
                stats.record_method("POST");
            }
            catch (...)
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.set(ngx::protocol::http::field::server, "ForwardEngine/1.0");
                resp.body(std::string_view(R"({"error":"Internal Server Error","message":"Failed to send captcha"})"));
                stats.increment_errors();
                stats.record_status_code(500);
            }

            co_return;
        }
    }

    /**
     * @namespace stats_api
     * @brief 统计 API 命名空间
     * @details 提供统计端点的 API 处理功能，包括统计快照、流量历史、性能指标等接口
     */
    namespace stats_api
    {
        /**
         * @struct traffic_history
         * @brief 流量历史结构体
         * @details 存储某一时间点的流量统计数据
         */
        struct traffic_history final
        {
            /// @brief 时间戳（毫秒）
            std::uint64_t timestamp{0};
            /// @brief 发送字节数
            std::uint64_t bytes_sent{0};
            /// @brief 接收字节数
            std::uint64_t bytes_received{0};
        };

        /**
         * @struct connections_response
         * @brief 连接列表响应结构体
         * @details 包装连接列表，与前端 dashboard.js 期望的格式一致
         */
        struct connections_response final
        {
            /// @brief 连接列表
            std::vector<connection_info> connections;
        };

        /**
         * @struct traffic_history_response
         * @brief 流量历史响应结构体
         * @details 存储流量历史 API 的响应数据
         */
        struct traffic_history_response final
        {
            /// @brief 流量历史记录列表
            std::vector<traffic_history> history;
            /// @brief 采样间隔（秒）
            std::uint32_t interval_seconds{60};
        };

        /**
         * @struct performance_metrics
         * @brief 性能指标结构体
         * @details 存储系统性能相关的指标数据
         */
        struct performance_metrics final
        {
            /// @brief CPU 使用率（百分比）
            double cpu_usage_percent{0.0};
            /// @brief 内存使用量（MB）
            double memory_usage_mb{0.0};
            /// @brief 活动线程数
            std::uint32_t active_threads{0};
            /// @brief IO 等待时间（百分比）
            double io_wait_percent{0.0};
        };

        /**
         * @brief 获取统计快照 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline auto get_stats(ngx::protocol::http::response &resp, const detailed_stats &stats)
            -> boost::asio::awaitable<void>
        {
            const auto snapshot = create_snapshot(stats);

            auto json_str = serialize(snapshot);

            if (json_str.empty())
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.body(std::string_view(R"({"error":"Failed to serialize stats","message":"JSON serialization error"})"));
                co_return;
            }

            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.set(ngx::protocol::http::field::cache_control, "no-cache");
            resp.body(std::string(json_str));
        }

        /**
         * @brief 获取活动连接列表 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline auto get_active_connections(ngx::protocol::http::response &resp, const detailed_stats &stats)
            -> boost::asio::awaitable<void>
        {
            const auto &active_list = stats.get_active_connections();
            const auto head = stats.connection_list_head.load(std::memory_order_relaxed);
            const std::size_t active_count = stats.active_connections.load(std::memory_order_relaxed);

            std::vector<connection_info> conn_list;
            conn_list.reserve(active_count);

            const std::size_t start = head >= detailed_stats::MAX_CONNECTIONS ? head - detailed_stats::MAX_CONNECTIONS : 0;
            const std::size_t end = head;

            for (std::size_t i = start; i < end && i < detailed_stats::MAX_CONNECTIONS; ++i)
            {
                const auto &info = active_list[i % detailed_stats::MAX_CONNECTIONS];
                if (info.client_port != 0)
                {
                    conn_list.push_back(info);
                }
            }

            connections_response response_data{std::move(conn_list)};
            const auto json_str = serialize(response_data);

            if (json_str.empty())
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.body(std::string_view(R"({"error":"Failed to serialize connections","message":"JSON serialization error"})"));
                co_return;
            }

            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.set(ngx::protocol::http::field::cache_control, "no-cache");
            resp.body(std::string(json_str));
        }

        /**
         * @brief 获取流量历史 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @param minutes 查询的时间范围（分钟）
         * @return 协程任务
         */
        inline auto get_traffic_history(ngx::protocol::http::response &resp, const detailed_stats &stats, const std::uint32_t minutes)
            -> boost::asio::awaitable<void>
        {
            traffic_history_response history_response;
            history_response.interval_seconds = 60;

            const auto now = std::chrono::steady_clock::now();
            const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - stats.start_time).count();
            const std::uint32_t total_seconds = static_cast<std::uint32_t>(uptime);
            const std::uint32_t requested_seconds = minutes * 60;
            const std::uint32_t data_points = std::min(total_seconds / 60, requested_seconds / 60);

            if (data_points > 0)
            {
                const auto total_sent = stats.bytes_sent.load(std::memory_order_relaxed);
                const auto total_received = stats.bytes_received.load(std::memory_order_relaxed);

                const auto avg_sent = total_sent / data_points;
                const auto avg_received = total_received / data_points;

                history_response.history.reserve(data_points);

                for (std::uint32_t i = 0; i < data_points; ++i)
                {
                    const auto point_time = now - std::chrono::seconds((data_points - i) * 60);
                    const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(point_time.time_since_epoch()).count();

                    traffic_history history;
                    history.timestamp = static_cast<std::uint64_t>(timestamp);
                    history.bytes_sent = avg_sent * (i + 1);
                    history.bytes_received = avg_received * (i + 1);

                    history_response.history.push_back(std::move(history));
                }
            }

            auto json_str = serialize(history_response);

            if (json_str.empty())
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.body(std::string_view(R"({"error":"Failed to serialize traffic history","message":"JSON serialization error"})"));
                co_return;
            }

            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.set(ngx::protocol::http::field::cache_control, "no-cache");
            resp.body(std::move(json_str));
        }

        /**
         * @brief 获取性能指标 API
         * @param resp HTTP 响应
         * @param stats 统计数据
         * @return 协程任务
         */
        inline auto get_performance(ngx::protocol::http::response &resp, const detailed_stats &stats)
            -> boost::asio::awaitable<void>
        {
            performance_metrics metrics;
            metrics.cpu_usage_percent = 0.0;
            metrics.memory_usage_mb = 0.0;
            metrics.active_threads = stats.active_connections.load(std::memory_order_relaxed);
            metrics.io_wait_percent = 0.0;

#ifdef _WIN32
            MEMORYSTATUSEX memory_status;
            memory_status.dwLength = sizeof(memory_status);
            if (GlobalMemoryStatusEx(&memory_status))
            {
                const std::uint64_t total_memory_mb = memory_status.ullTotalPhys / (1024 * 1024);
                const std::uint64_t available_memory_mb = memory_status.ullAvailPhys / (1024 * 1024);
                metrics.memory_usage_mb = static_cast<double>(total_memory_mb - available_memory_mb);
            }

            FILETIME idle_time;
            FILETIME kernel_time;
            FILETIME user_time;
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

            if (json_str.empty())
            {
                resp.status(ngx::protocol::http::status::internal_server_error);
                resp.set(ngx::protocol::http::field::content_type, "application/json");
                resp.body(std::string_view(R"({"error":"Failed to serialize performance metrics","message":"JSON serialization error"})"));
                co_return;
            }

            resp.status(ngx::protocol::http::status::ok);
            resp.set(ngx::protocol::http::field::content_type, "application/json");
            resp.set(ngx::protocol::http::field::cache_control, "no-cache");
            resp.body(std::string(json_str));
        }
    }
}

/**
 * @brief glaze JSON 序列化模板特化：商品结构体
 */
template <>
struct glz::meta<srv::processor::main_api::product>
{
    using T = srv::processor::main_api::product;
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
        "rating", &T::rating,
        "specs", &T::specs,
        "reviews", &T::reviews,
        "detail", &T::detail);
};

/**
 * @brief glaze JSON 序列化模板特化：商品规格结构体
 */
template <>
struct glz::meta<srv::processor::main_api::product_spec>
{
    using T = srv::processor::main_api::product_spec;
    static constexpr auto value = glz::object(
        "name", &T::name,
        "value", &T::value);
};

/**
 * @brief glaze JSON 序列化模板特化：商品评价结构体
 */
template <>
struct glz::meta<srv::processor::main_api::product_review>
{
    using T = srv::processor::main_api::product_review;
    static constexpr auto value = glz::object(
        "author", &T::author,
        "rating", &T::rating,
        "content", &T::content,
        "date", &T::date);
};

/**
 * @brief glaze JSON 序列化模板特化：商品列表响应结构体
 */
template <>
struct glz::meta<srv::processor::main_api::products_response>
{
    using T = srv::processor::main_api::products_response;
    static constexpr auto value = glz::object(
        "items", &T::items,
        "total", &T::total,
        "page", &T::page,
        "page_size", &T::page_size);
};

/**
 * @brief glaze JSON 序列化模板特化：购物车商品结构体
 */
template <>
struct glz::meta<srv::processor::main_api::cart_item>
{
    using T = srv::processor::main_api::cart_item;
    static constexpr auto value = glz::object(
        "id", &T::id,
        "name", &T::name,
        "quantity", &T::quantity,
        "price", &T::price,
        "image", &T::image,
        "stock", &T::stock,
        "spec", &T::spec);
};

/**
 * @brief glaze JSON 序列化模板特化：购物车响应结构体
 */
template <>
struct glz::meta<srv::processor::main_api::cart_response>
{
    using T = srv::processor::main_api::cart_response;
    static constexpr auto value = glz::object(
        "items", &T::items,
        "total_items", &T::total_items,
        "total_price", &T::total_price);
};

/**
 * @brief glaze JSON 序列化模板特化：搜索响应结构体
 */
template <>
struct glz::meta<srv::processor::main_api::search_response>
{
    using T = srv::processor::main_api::search_response;
    static constexpr auto value = glz::object(
        "results", &T::results,
        "total", &T::total,
        "query", &T::query);
};

/**
 * @brief glaze JSON 序列化模板特化：流量历史结构体
 */
template <>
struct glz::meta<srv::processor::stats_api::traffic_history>
{
    using T = srv::processor::stats_api::traffic_history;
    static constexpr auto value = glz::object(
        "timestamp", &T::timestamp,
        "bytes_sent", &T::bytes_sent,
        "bytes_received", &T::bytes_received);
};

/**
 * @brief glaze JSON 序列化模板特化：连接列表响应结构体
 */
template <>
struct glz::meta<srv::processor::stats_api::connections_response>
{
    using T = srv::processor::stats_api::connections_response;
    static constexpr auto value = glz::object(
        "connections", &T::connections);
};

/**
 * @brief glaze JSON 序列化模板特化：流量历史响应结构体
 */
template <>
struct glz::meta<srv::processor::stats_api::traffic_history_response>
{
    using T = srv::processor::stats_api::traffic_history_response;
    static constexpr auto value = glz::object(
        "history", &T::history,
        "interval_seconds", &T::interval_seconds);
};

/**
 * @brief glaze JSON 序列化模板特化：性能指标结构体
 */
template <>
struct glz::meta<srv::processor::stats_api::performance_metrics>
{
    using T = srv::processor::stats_api::performance_metrics;
    static constexpr auto value = glz::object(
        "cpu_usage_percent", &T::cpu_usage_percent,
        "memory_usage_mb", &T::memory_usage_mb,
        "active_threads", &T::active_threads,
        "io_wait_percent", &T::io_wait_percent);
};
