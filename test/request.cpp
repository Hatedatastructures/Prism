#include <http/constants.hpp>
#include <http/request.hpp>

#include <http/response.hpp>

#include <http/serialization.hpp>
#include <http/deserialization.hpp>
#include <memory/container.hpp>
#include <agent/obscura.hpp>
#include <iostream>
#include <string>


namespace http = ngx::http;
namespace agent = ngx::agent;



void serialization()
{
    http::request req;

    req.method(http::verb::post);
    req.target("/api/v1/user");
    req.version(11);

    req.set("Host", "example.com");
    req.set("User-Agent", "ForwardEngine/0.1");

    req.set(http::field::content_type, "application/json");

    // req.body(memory::string("({"name":"test","age":18})"));

    req.keep_alive(true);

    auto host = req.at(http::field::host);
    auto ua   = req.at("User-Agent");

    const auto str_value = http::serialize(req);
    std::cout << str_value << std::endl;
}

void deserialization()
{
    const std::string request_str =
        "POST /api/v1/user HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: ForwardEngine/0.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 24\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "{\"name\":\"test\",\"age\":18}";

    if (http::request req; http::deserialize(request_str, req))
    {
        std::cout << "request" << std::endl;
        std::cout << http::serialize(req) << std::endl << std::endl << std::endl;
    }
    else
    {
        std::cout << "deserialize failed" << std::endl;
    }

    const std::string response_str =
        "HTTP/1.1 200 OK\r\n"
        "Host: example.com\r\n"
        "User-Agent: ForwardEngine/0.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 26\r\n"
        "\r\n"
        "{\"name\":\"test\",\"age\":18}";

    if (http::response resp; http::deserialize(response_str, resp))
    {
        std::cout << "response" << std::endl;
        std::cout << http::serialize(resp) << std::endl;
    }
    else
    {
        std::cout << "deserialize failed" << std::endl;
    }
}
// TODO: add more tests
int main()
{
    serialization();
    deserialization();
    return 0;
}

