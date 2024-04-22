OPTION(TLS_PLAYGROUND_FUZZ_TESTING "Enable fuzz testing")
if (TLS_PLAYGROUND_FUZZ_TESTING)
  add_executable(fuzz_tester fuzz_tester.cpp)
  target_link_libraries(fuzz_tester PUBLIC tls-playground-compiler_options tls-playground-lib -fsanitize=fuzzer,undefined,address)
  target_compile_options(fuzz_tester PRIVATE -fsanitize=fuzzer,undefined,address)

  SET(TLS_PLAYGROUND_FUZZ_RUNTIME 10 CACHE STRING "Number of seconds to run fuzz testing")

  add_test(NAME fuzz_tester_run COMMAND fuzz_tester -max_total_time=${TLS_PLAYGROUND_FUZZ_RUNTIME})
endif ()