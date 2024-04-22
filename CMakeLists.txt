cmake_minimum_required(VERSION 3.26)
project(tls_playground)

option(TLS_PLAYGROUND_WARNINGS_AS_ERRORS "Treat compiler warnings as errors")


add_library(tls-playground-compiler_options INTERFACE)
target_compile_features(tls-playground-compiler_options INTERFACE cxx_std_20)
if (MSVC)
  target_compile_options(tls-playground-compiler_options INTERFACE /W4)
  if (TLS_PLAYGROUND_WARNINGS_AS_ERRORS)
    target_compile_options(tls-playground-compiler_options INTERFACE /WX)
  endif ()
else ()
  target_compile_options(tls-playground-compiler_options INTERFACE -Wall -Wextra -Wpedantic)
  if (TLS_PLAYGROUND_WARNINGS_AS_ERRORS)
    target_compile_options(tls-playground-compiler_options INTERFACE -Werror)
  endif ()
  if (OPT_ENABLE_COVERAGE)
    if (CMAKE_COMPILER_IS_GNUCXX)
      target_compile_options(tls-playground-compiler_options INTERFACE -fprofile-arcs -ftest-coverage)
      target_link_options(tls-playground-compiler_options INTERFACE -lgcov --coverage)
    endif ()
  endif ()
endif ()

add_subdirectory(src)

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  include(FetchContent)

  FetchContent_Declare(
      Catch2
      GIT_REPOSITORY https://github.com/catchorg/Catch2.git
      GIT_TAG v3.4.0
      GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(Catch2)

  enable_testing()
  add_subdirectory(test)
  add_subdirectory(fuzz_test)

  include(CTest)
endif ()