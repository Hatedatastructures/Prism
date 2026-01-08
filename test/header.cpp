#include <http/header.hpp>
#include <iostream>
#include <string>
#include <cassert>
#include <vector>

#ifdef WIN32
    #include <windows.h>
#endif

#include "memory/pool.hpp"

namespace http = ngx::http;

/**
 * @brief 测试 `headers` 类的基本操作
 */
void test_basic_operations()
{
    std::cout << "=== 开始基本操作测试 ===" << std::endl;
    http::headers h;

    // 测试空状态
    assert(h.empty());
    assert(h.size() == 0);

    // 测试添加头字段
    h.construct("Content-Type", "text/html");
    h.construct("Content-Length", "1024");
    h.construct("Server", "ForwardEngine/1.0");

    assert(!h.empty());
    assert(h.size() == 3);

    // 测试检索
    assert(h.retrieve("Content-Type") == "text/html");
    assert(h.retrieve("content-type") == "text/html"); // 测试大小写不敏感
    assert(h.retrieve("CONTENT-LENGTH") == "1024");
    assert(h.retrieve("Server") == "ForwardEngine/1.0");
    assert(h.retrieve("Non-Existent").empty());

    // 测试包含判断
    assert(h.contains("Content-Type"));
    assert(h.contains("CONTENT-TYPE"));
    assert(!h.contains("X-Forwarded-For"));

    std::cout << "基本操作测试通过！" << std::endl;
}

/**
 * @brief 测试 `headers` 类的修改和删除操作
 */
void test_modification_and_removal()
{
    std::cout << "=== 开始修改和删除测试 ===" << std::endl;
    http::headers h;

    h.set("Cache-Control", "no-cache");
    assert(h.retrieve("Cache-Control") == "no-cache");

    // 测试更新现有字段
    h.set("Cache-Control", "max-age=3600");
    assert(h.size() == 1);
    assert(h.retrieve("Cache-Control") == "max-age=3600");

    // 测试删除字段
    bool erased = h.erase("Cache-Control");
    assert(erased);
    assert(h.empty());
    assert(!h.contains("Cache-Control"));

    // 测试删除不存在的字段
    erased = h.erase("Non-Existent");
    assert(!erased);

    // 测试按键值对删除
    h.construct("Set-Cookie", "id=123");
    h.construct("Set-Cookie", "name=test");
    assert(h.size() == 2);

    erased = h.erase("Set-Cookie", "id=123");
    assert(erased);
    assert(h.size() == 1);
    assert(h.retrieve("Set-Cookie") == "name=test");

    std::cout << "修改和删除测试通过！" << std::endl;
}

/**
 * @brief 测试 `headers` 类的迭代功能
 */
void test_iteration()
{
    std::cout << "=== 开始迭代功能测试 ===" << std::endl;
    http::headers h;

    h.construct("Header1", "Value1");
    h.construct("Header2", "Value2");
    h.construct("Header3", "Value3");

    const std::vector<std::pair<std::string_view, std::string_view>> expected = {
        {"header1", "Value1"},
        {"header2", "Value2"},
        {"header3", "Value3"}};

    size_t count = 0;
    for (const auto &entry : h)
    {
        assert(entry.key.view() == expected[count].first);
        assert(std::string_view(entry.value) == expected[count].second);
        count++;
    }
    assert(count == 3);

    std::cout << "迭代功能测试通过！" << std::endl;
}

/**
 * @brief 测试 `headers` 类的清空和空间预留
 */
void test_clear_and_reserve()
{
    std::cout << "=== 开始清空和预留测试 ===" << std::endl;
    http::headers h;

    h.reserve(10);
    h.construct("A", "1");
    h.construct("B", "2");
    assert(h.size() == 2);

    h.clear();
    assert(h.empty());
    assert(h.size() == 0);
    assert(!h.contains("A"));

    std::cout << "清空和预留测试通过！" << std::endl;
}

int main()
{
    ngx::memory::system::enable_global_pooling();
    SetConsoleOutputCP(CP_UTF8);
    std::cout << "HTTP 头字段模块测试启动..." << std::endl;

    try
    {
        test_basic_operations();
        test_modification_and_removal();
        test_iteration();
        test_clear_and_reserve();

        std::cout << "\n所有 HTTP 头字段测试全部通过！" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "测试过程中捕获到异常: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
