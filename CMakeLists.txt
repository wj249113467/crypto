#############生成可执行文件###############
cmake_minimum_required(VERSION 2.8)

project(crypto)
set(CMAKE_CXX_STANDARD 11)
add_executable(crypto crypto.c
		md5.c
		des.c
		platform.c
		platform_util.c)
		
#############生成lib库(需要删除 crypto.c 内的main函数)###############

#aux_source_directory(. DIR_HELLO_SRCS)
#add_library(crypto ${DIR_HELLO_SRCS})