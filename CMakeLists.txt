cmake_minimum_required(VERSION 3.0.0)
project(skcp VERSION 0.1.0)

# -std=c89
SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wno-deprecated-declarations -DDEBUG -ggdb -fsanitize=address")
#SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -DDEBUG -g -ggdb ")
SET(CMAKE_C_FLAGS_RELEASE "$ENV{CXXFLAGS} -std=c89 -O3 -Wall")

message("project dir: ${PROJECT_SOURCE_DIR}")

include_directories(${PROJECT_SOURCE_DIR}/src/)
aux_source_directory(${PROJECT_SOURCE_DIR}/src DIR_SRCS)

# ############# skcp #############
add_library(skcp SHARED ${DIR_SRCS})
target_link_libraries(skcp ssl)
target_link_libraries(skcp crypto)
target_link_libraries(skcp ev)

# ############# test #############
aux_source_directory(${PROJECT_SOURCE_DIR}/test DIR_TEST)
add_executable(test_skcp_server ${DIR_SRCS} "${PROJECT_SOURCE_DIR}/test/test_skcp_server.c")
target_link_libraries(test_skcp_server ssl)
target_link_libraries(test_skcp_server crypto)
target_link_libraries(test_skcp_server ev)

#aux_source_directory(${PROJECT_SOURCE_DIR}/test DIR_TEST)
#add_executable(test_skcp ${DIR_SRCS} ${DIR_TEST})
#target_link_libraries(test_skcp ssl)
#target_link_libraries(test_skcp crypto)
#target_link_libraries(test_skcp ev)


