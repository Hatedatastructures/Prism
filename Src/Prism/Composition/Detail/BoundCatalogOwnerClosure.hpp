/** @file BoundCatalogOwnerClosure.hpp @brief BoundCatalog owner 关闭的私有模板实现。 */
#pragma once

#include <Prism/Composition/Provider/BoundCatalog.hpp>

namespace Prism::Composition::Provider
{
    template<typename T>
    auto BoundCatalog::CloseOwner(const T& Owner) noexcept -> void
    {
        if constexpr(requires{Owner->Close();})
        {
            if (Owner)
            {
                Owner->Close();
            }
        }
    }
}
