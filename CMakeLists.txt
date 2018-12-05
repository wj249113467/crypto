# cmake_minimum_required(VERSION 2.8)
# project(main)
#
# set(CMAKE_CXX_STANDARD 11)
#
# add_executable(main crypto.c
# 		md5.c
#       des.c
#       platform.c
#       platform_util.c)

aux_source_directory(. DIR_HELLO_SRCS)
add_library(crypto ${DIR_HELLO_SRCS})