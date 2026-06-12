include(KinetAlgorithm)
kinet_add_algorithm(
    NAME    ntt
    SOURCES cpp/ntt.cpp cpp/ntt_large.cpp
    CABI    c-abi/c_ntt.cpp
)

# Body in cpp/ntt.cpp + cpp/ntt_large.cpp; C-ABI shim in c-abi/c_ntt.cpp.
target_include_directories(ntt_cpu PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cpp)
target_include_directories(ntt     PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cpp)

# GPU host-side drivers for the large-N path. These compile as plain C++ on
# every host (no CUDA/Metal/wgpu runtime required); when CRYPTO_ENABLE_*
# is on the corresponding kernel files in gpu/{cuda,metal,wgsl}/ are added
# to the link line. Today the drivers fall through to the CPU oracle so
# byte-equality is exercised on every CI runner.
add_library(ntt_large_gpu_cuda  STATIC gpu/cuda/ntt_large.cu)
set_source_files_properties(gpu/cuda/ntt_large.cu PROPERTIES LANGUAGE CXX)
target_compile_features(ntt_large_gpu_cuda  PUBLIC cxx_std_20)
target_include_directories(ntt_large_gpu_cuda PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cpp)
set_target_properties(ntt_large_gpu_cuda PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(ntt_large_gpu_cuda PUBLIC ntt_cpu)

add_library(ntt_large_gpu_metal STATIC gpu/metal/ntt_large_driver.cpp)
target_compile_features(ntt_large_gpu_metal PUBLIC cxx_std_20)
target_include_directories(ntt_large_gpu_metal PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cpp)
set_target_properties(ntt_large_gpu_metal PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(ntt_large_gpu_metal PUBLIC ntt_cpu)

add_library(ntt_large_gpu_wgsl  STATIC gpu/wgsl/ntt_large_driver.cpp)
target_compile_features(ntt_large_gpu_wgsl PUBLIC cxx_std_20)
target_include_directories(ntt_large_gpu_wgsl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cpp)
set_target_properties(ntt_large_gpu_wgsl PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(ntt_large_gpu_wgsl PUBLIC ntt_cpu)
