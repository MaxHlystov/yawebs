set(CMAKE_LEGACY_CYGWIN_WIN32 0)

cmake_minimum_required (VERSION 2.8) 
 
set (PROJECT final) 
 
project (${PROJECT}) 
 
set (HEADERS 
	yawebs.hpp)
 
set (SOURCES 
	yawebs.cpp) 

add_executable (${PROJECT} ${HEADERS} ${SOURCES})
