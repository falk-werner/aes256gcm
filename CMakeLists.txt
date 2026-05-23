cmake_minimum_required(VERSION 3.20)
project(aes256gcm VERSION 1.0.0)

option(WITHOUT_TESTS "Disable build of Unit Tests." OFF)
option(WITH_COVERAGE "Enable code coverage." OFF)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_library(aes256gcm STATIC
    ${CMAKE_CURRENT_BINARY_DIR}/aes256gcm_version.cpp

    lib/aes256gcm/rand.cpp
    lib/aes256gcm/pbkdf2.cpp
    lib/aes256gcm/openssl_error.cpp
    lib/aes256gcm/encrypter.cpp
    lib/aes256gcm/decrypter.cpp
    lib/aes256gcm/verifier.cpp
    lib/aes256gcm/secure_string.cpp
    
    lib/aes256gcm/proprietary/encryption_info.cpp
    lib/aes256gcm/proprietary/encrypt_file.cpp
    lib/aes256gcm/proprietary/decrypt_file.cpp
    lib/aes256gcm/proprietary/verify_file.cpp
    lib/aes256gcm/proprietary/get_encryption_info.cpp
    lib/aes256gcm/proprietary/encrypt_file_inplace.cpp
    lib/aes256gcm/proprietary/decrypt_file_inplace.cpp
    lib/aes256gcm/proprietary/encrypt_file_tostream.cpp
    lib/aes256gcm/proprietary/decrypt_file_tostream.cpp
    lib/aes256gcm/proprietary/memmapped_file.cpp

    lib/aes256gcm/cli/run.cpp
    lib/aes256gcm/cli/context.cpp
    lib/aes256gcm/cli/print_usage.cpp
    lib/aes256gcm/cli/print_info.cpp
    lib/aes256gcm/cli/encrypt.cpp
    lib/aes256gcm/cli/decrypt.cpp
    lib/aes256gcm/cli/verify.cpp
)
target_link_libraries(aes256gcm PUBLIC OpenSSL::Crypto)
target_include_directories(aes256gcm PUBLIC inc)
target_include_directories(aes256gcm PRIVATE lib)

configure_file(${CMAKE_CURRENT_LIST_DIR}/lib/aes256gcm/version.cpp.in ${CMAKE_CURRENT_BINARY_DIR}/aes256gcm_version.cpp @ONLY)

add_executable(aes256gcm_app src/main.cpp)
target_link_libraries(aes256gcm_app PRIVATE aes256gcm)
set_target_properties(aes256gcm_app PROPERTIES OUTPUT_NAME aes256gcm)
install(TARGETS aes256gcm_app)

if(NOT(WITHOUT_TESTS))

enable_testing()
include(CTest)

find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(alltests
    test-src/test_pbkdf2.cpp
    test-src/test_xcrypt.cpp
    test-src/test_xcrypt_file.cpp
    test-src/test_secure_string.cpp
    test-src/test_cli.cpp
)
target_link_libraries(alltests PRIVATE aes256gcm GTest::gtest GTest::gtest_main)
target_include_directories(alltests PRIVATE lib)

gtest_discover_tests(alltests)

if(WITH_COVERAGE)
target_compile_options(aes256gcm PUBLIC -coverage)
target_link_options(aes256gcm PUBLIC -coverage)

add_custom_target(coverage
    mkdir -p coverage
	COMMAND ./alltests
	COMMAND gcovr --html-details coverage/index.html -r .. -e ../test -e ../src 
)
add_dependencies(coverage alltests)

endif()


endif()
