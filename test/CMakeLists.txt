file(GLOB source *.cpp)

add_executable(tests ${source})
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain tls-playground-compiler_options tls-playground-lib)

include(Catch)
catch_discover_tests(tests)