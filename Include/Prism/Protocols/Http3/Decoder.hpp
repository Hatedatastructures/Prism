/**
 * @file Decoder.hpp
 * @brief QPACK 头块解码结果与接口。
 */
#pragma once

#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>

#include <cstdint>
#include <span>
#include <string>

namespace Prism::Http3::Qpack
{
    struct HeaderField final
    {
        std::string Name;
        std::string value;
    };

    /** @brief 解码 QPACK 头块；输入借用至调用返回，失败返回空集合。 */
    [[nodiscard]] auto DecodeHeaderBlock(
        std::span<const std::uint8_t> Data,
        Prism::Memory::ResourcePointer MemoryResource)
        -> Prism::Memory::Vector<HeaderField>;
}
