set(CMAKE_LEGACY_CYGWIN_WIN32 0)

cmake_minimum_required (VERSION 2.8) 
 
set (PROJECT final) 
 
project (${PROJECT}) 
 
set (HEADERS 
	yawebs.hpp)
 
set (SOURCES 
	yawebs.cpp) 

find_package(Threads REQUIRED)
if(THREADS_HAVE_PTHREAD_ARG)
  target_compile_options(PUBLIC ${PROJECT} "-pthread")
endif()


add_executable (${PROJECT} ${HEADERS} ${SOURCES})

if(CMAKE_THREAD_LIBS_INIT)
  target_link_libraries(${PROJECT} "${CMAKE_THREAD_LIBS_INIT}")
endif()