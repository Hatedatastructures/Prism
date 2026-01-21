#include <glaze/glaze.hpp>
#include <iostream>
#include <string>
#include <vector>

// 1. 修改结构体首字母大写，避免与变量名冲突
struct Person
{
    std::string name;
    int age;
    std::vector<std::string> hobbies;
};

int main()
{
    Person person{"Alice", 30, {"reading", "swimming"}};

    // 2. 修复 write_json 调用
    // 方法 A (推荐): 使用 .value() 获取结果，如果出错会抛出异常 (或使用 .value_or(""))
    // std::string json = glz::write_json(person).value();

    // 方法 B (更高效): 传入 buffer 进行写入，避免额外的移动/拷贝，且返回值是错误码
    std::string json;
    if (auto ec = glz::write_json(person, json))
    {
        std::cerr << "Serialize failed" << std::endl;
        return 1;
    }

    std::cout << "JSON: " << json << std::endl;

    // 3. 现在 Person 类型名可用，不会被变量名屏蔽
    Person person2;
    if (auto ec2 = glz::read_json(person2, json))
    {
        std::cerr << "Deserialize failed" << std::endl;
        return 1;
    }

    return 0;
}
