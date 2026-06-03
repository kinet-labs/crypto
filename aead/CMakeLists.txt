# aead - ChaCha20-Poly1305 + AES-GCM (no CPU body in cevm; Phase 3 authors)
include(KinetAlgorithm)
kinet_add_algorithm(NAME aead SOURCES c-abi/c_aead.cpp CABI c-abi/c_aead.cpp)
