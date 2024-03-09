file(GLOB source *.cpp)

add_library(tls-playground-lib ${source})
target_include_directories(tls-playground-lib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(tls-playground-lib PRIVATE tls-playground-compiler_options)