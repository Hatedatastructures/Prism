#include <http/header.hpp>
#include <cctype>
#include <iterator>

namespace ngx::http
{
    downcase_string::downcase_string(memory::resource_pointer mr)
        : str_(mr)
    {
    }

    downcase_string::downcase_string(std::string_view str, memory::resource_pointer mr)
        : str_(mr)
    {
        str_.reserve(str.size());
        std::ranges::transform(str, std::back_inserter(str_), ::tolower);
    }

    /**
     * @brief 获取 downcase_string 的原始字符串值
     * @return const memory::string& 原始字符串值
     */
    const memory::string &downcase_string::value() const
    {
        return str_;
    }

    /**
     * @brief 获取 downcase_string 的原始字符串视图
     * @return std::string_view 原始字符串视图
     */
    std::string_view downcase_string::view() const
    {
        return str_;
    }

    bool downcase_string::operator==(const downcase_string &other) const
    {
        return str_ == other.str_;
    }

    headers::header::header(memory::resource_pointer mr)
        : key(mr), value(mr), original_key(mr)
    {
    }

    headers::header::header(const std::string_view name, const std::string_view value, memory::resource_pointer mr)
        : key(name, mr), value(mr), original_key(mr)
    {
        this->value.assign(value.begin(), value.end());
        this->original_key.assign(name.begin(), name.end());
    }

    headers::headers(memory::resource_pointer mr)
        : entries_(mr)
    {
    }

    memory::resource_pointer headers::resource() const noexcept
    {
        return entries_.get_allocator().resource();
    }

    /**
     * @brief 清空 headers 容器
     */
    void headers::clear() noexcept
    {
        entries_.clear();
    }

    /**
     * @brief 预留 headers 容器空间
     * @param count 需要预留的空间大小
     */
    void headers::reserve(const size_type count)
    {
        entries_.reserve(count);
    }

    /**
     * @brief 获取 headers 容器大小
     * @return size_type headers 容器大小
     */
    headers::size_type headers::size() const noexcept
    {
        return entries_.size();
    }

    /**
     * @brief 判断 headers 容器是否为空
     * @return true headers 容器为空
     * @return false headers 容器不为空
     */
    bool headers::empty() const noexcept
    {
        return entries_.empty();
    }

    /**
     * @brief 生成 downcase_string 键
     * @param name 原始字符串键
     * @return downcase_string 转换后的 downcase_string 键
     */
    downcase_string headers::make_key(const std::string_view name) const
    {
        return downcase_string{name, resource()};
    }

    /**
     * @brief 构造 headers 容器元素
     * @param name 原始字符串键
     * @param value 原始字符串值
     */
    void headers::construct(std::string_view name, std::string_view value)
    {
        entries_.emplace_back(name, value, resource());
    }

    /**
     * @brief 构造 headers 容器元素
     * @param entry 要构造的 header 元素
     */
    void headers::construct(const header &entry)
    {
        construct(std::string_view{entry.original_key}, std::string_view{entry.value});
    }

    /**
     * @brief 设置 headers 容器元素
     * @param name 原始字符串键
     * @param value 原始字符串值
     */
    void headers::set(const std::string_view name, const std::string_view value)
    {
        downcase_string key = make_key(name);
        bool found = false;

        for (auto &entry : entries_)
        {
            if (entry.key == key)
            {
                if (!found)
                {
                    entry.original_key.assign(name);
                    entry.value.assign(value);
                    found = true;
                }
                else
                {   // 防止中间删除迭代器导致的巨大性能开销和内存开销
                    entry.value.clear();
                    entry.original_key.clear();
                }
            }
        }

        if (!found)
        {
            construct(name, value);
        }
    }

    bool headers::erase(const std::string_view name)
    {
        if (entries_.empty())
        {
            return false;
        }

        const downcase_string key = make_key(name);
        const auto old_size = entries_.size();

        std::erase_if(entries_, [&](const header &entry) { return entry.key == key; });

        return entries_.size() != old_size;
    }

    bool headers::erase(const std::string_view name, const std::string_view value)
    {
        if (entries_.empty())
        {
            return false;
        }

        downcase_string key = make_key(name);
        const auto old_size = entries_.size();

        std::erase_if(entries_, [&](const header &entry)
        {
            return entry.key == key && entry.value == value;
        });

        return entries_.size() != old_size;
    }

    /**
     * @brief 判断 headers 容器是否包含指定键
     * @param name 原始字符串键
     * @return true 包含指定键
     * @return false 不包含指定键
     */
    bool headers::contains(const std::string_view name) const noexcept
    {
        if (entries_.empty())
        {
            return false;
        }

        const downcase_string key = make_key(name);

        for (const auto &entry : entries_)
        {
            if (entry.key == key && !entry.value.empty())
            {
                return true;
            }
        }

        return false;
    }

    /**
     * @brief 获取 headers 容器元素值
     * @param name 原始字符串键
     * @return std::string_view 元素值
     */
    std::string_view headers::retrieve(const std::string_view name) const noexcept
    {
        if (entries_.empty())
        {
            return {};
        }

        const downcase_string key = make_key(name);

        for (const auto &entry : entries_)
        {
            if (entry.key == key && !entry.value.empty())
            {
                return entry.value;
            }
        }

        return {};
    }

    /**
     * @brief 获取 headers 容器元素迭代器
     * @return headers::iterator 元素迭代器
     */
    headers::iterator headers::begin() const
    {
        return entries_.begin();
    }


    /**
     * @brief 获取 headers 容器元素迭代器
     * @return headers::iterator 元素迭代器
     */
    headers::iterator headers::end() const
    {
        return entries_.end();
    }

} // namespace ngx::http
