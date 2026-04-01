#include <prism/agent/account/directory.hpp>

namespace psm::agent::account
{
    directory::directory(const memory::resource_pointer resource)
        : allocator_(resource), entries_ptr_()
    {   // 初始化账户目录
        entries_ptr_.store(std::allocate_shared<unordered_map>(allocator_, 0));
    }

    void directory::reserve(const std::size_t n)
    {
        auto update_function = [n](unordered_map &ref)
        {   // 预留账户条目容量
            ref.reserve(n);
        };
        update_entries(update_function);
    }

    void directory::clear()
    {
        entries_ptr_.store(std::allocate_shared<unordered_map>(allocator_, 0), std::memory_order_release);
    }

    void directory::upsert(std::string_view credential, const std::uint32_t max_connections)
    {
        auto update_function = [credential, max_connections](unordered_map &ref)
        {   // 创建插入或更新用户条目
            auto &entry_ptr = ref[memory::string(credential, ref.get_allocator().resource())];
            if (!entry_ptr)
            {
                entry_ptr = std::allocate_shared<entry>(ref.get_allocator());
            }
            entry_ptr->max_connections = max_connections;
        };
        update_entries(update_function);
    }

    auto directory::find(const std::string_view credential) const noexcept -> std::shared_ptr<entry>
    {   // 先获取当前映射表的快照，确保读取的是最新数据
        const auto snapshot = entries_ptr_.load(std::memory_order_acquire);
        if (!snapshot)
        {
            return nullptr;
        }

        const auto it = snapshot->find(credential);
        if (it == snapshot->end())
        {   // 如果未找到，返回 nullptr
            return nullptr;
        }

        return it->second;
    }
} // namespace psm::agent::account
