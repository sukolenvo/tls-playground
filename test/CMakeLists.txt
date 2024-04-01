file(GLOB source *.cpp)

add_executable(tests ${source})
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain tls-playground-compiler_options tls-playground-lib)

include(Catch)
catch_discover_tests(tests)

add_custom_command(TARGET tests POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/resources ${CMAKE_CURRENT_BINARY_DIR}/resources)
