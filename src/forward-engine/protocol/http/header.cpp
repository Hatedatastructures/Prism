#include <forward-engine/protocol/http/header.hpp>
#include <cctype>
#include <iterator>

namespace ngx::protocol::http
{
    downcase_string::downcase_string(const memory::resource_pointer mr)
        : str_(mr)
    {
    }

    downcase_string::downcase_string(std::string_view str, const memory::resource_pointer mr)
        : str_(mr)
    {
        str_.reserve(str.size());
        std::ranges::transform(str, std::back_inserter(str_), ::tolower);
    }

    auto downcase_string::value() const
        -> const memory::string &
    {
        return str_;
    }

    auto downcase_string::view() const
        -> std::string_view
    {
        return str_;
    }

    auto downcase_string::operator==(const downcase_string &other) const
        -> bool
    {
        return str_ == other.str_;
    }

    headers::header::header(const memory::resource_pointer mr)
        : key(mr), value(mr), original_key(mr)
    {
    }

    headers::header::header(const std::string_view name, const std::string_view value, const memory::resource_pointer mr)
        : key(name, mr), value(mr), original_key(mr)
    {
        this->value.assign(value.begin(), value.end());
        this->original_key.assign(name.begin(), name.end());
    }

    headers::headers(const memory::resource_pointer mr)
        : entries_(mr)
    {
    }

    auto headers::resource() const noexcept
        -> memory::resource_pointer
    {
        return entries_.get_allocator().resource();
    }

    void headers::clear() noexcept
    {
        entries_.clear();
    }

    void headers::reserve(const size_type count)
    {
        entries_.reserve(count);
    }

    auto headers::size() const noexcept
        -> headers::size_type
    {
        return entries_.size();
    }

    auto headers::empty() const noexcept
        -> bool
    {
        return entries_.empty();
    }

    auto headers::make_key(const std::string_view name) const
        -> downcase_string
    {
        return downcase_string{name, resource()};
    }

    void headers::construct(std::string_view name, std::string_view value)
    {
        entries_.emplace_back(name, value, resource());
    }

    void headers::construct(const header &entry)
    {
        construct(std::string_view{entry.original_key}, std::string_view{entry.value});
    }

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

    auto headers::erase(const std::string_view name)
        -> bool
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

    auto headers::erase(const std::string_view name, const std::string_view value)
        -> bool
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

    auto headers::contains(const std::string_view name) const noexcept
        -> bool
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

    auto headers::retrieve(const std::string_view name) const noexcept
        -> std::string_view
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

    auto headers::begin() const
        -> headers::iterator
    {
        return entries_.begin();
    }


    auto headers::end() const
        -> headers::iterator
    {
        return entries_.end();
    }

} // namespace ngx::protocol::http
