#include <transformer.hpp>
#include <memory.hpp>
#include <trace.hpp>
#include <iostream>
#include <vector>

namespace json = psm::transformer::json;
namespace trace = psm::trace;

struct product
{
    std::string name;
    int price;
};


struct order
{
    std::string customer_name;
    std::vector<product> products;
};

void init()
{
    psm::memory::system::enable_global_pooling();

    trace::config config;
    config.file_name = "forward.log";
    config.path_name = "logs";
    config.max_size = 64U * 1024U * 1024U;
    config.max_files = 8U;
    config.queue_size = 8192U;
    config.enable_console = true;
    config.enable_file = false;
    config.thread_count = 1U;
    trace::init(config);
}
int main()
{
    init();
    psm::memory::string product_json(psm::memory::current_resource());
    if (!json::serialize(product{"apple", 100}, product_json))
    {
        trace::error("serialize failed");
        return 1;
    }
    trace::info("product json: {}", product_json);

    psm::memory::string order_json(psm::memory::current_resource());
    if (!json::serialize(order{"customer1", {{"apple", 100}, {"orange", 200}}}, order_json))
    {
        trace::error("serialize failed");
        return 1;
    }
    trace::info("order json: {}", order_json);

    return 0;
}
