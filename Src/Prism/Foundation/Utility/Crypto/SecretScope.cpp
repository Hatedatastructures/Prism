/**
 * @file SecretScope.cpp
 * @brief 借用秘密缓冲区的可靠擦除实现。
 */
#include <Prism/Foundation/Utility/Crypto/SecretScope.hpp>

#include <openssl/mem.h>

namespace Prism::Crypto
{
    SecretScope::~SecretScope()
    {
        if (!Bytes_.empty())
        {
            OPENSSL_cleanse(Bytes_.data(), Bytes_.size());
        }
    }
} // namespace Prism::Crypto
