set(PrismProtocolHttpCompressionHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/HttpCompression/Huffman.hpp"
)
PrismAddStaticTarget(PrismProtocolHttpCompression
    SOURCES
        Huffman.cpp
    HEADERS ${PrismProtocolHttpCompressionHeaders}
)
