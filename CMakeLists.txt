cmake_minimum_required(VERSION 3.9)
project(sleigh)

set(CMAKE_CXX_STANDARD 20)

set(sleigh_source
    sleigh/address.cc
    sleigh/context.cc
    sleigh/float.cc
    sleigh/globalcontext.cc
    sleigh/marshal.cc
    sleigh/opcodes.cc
    sleigh/pcodecompile.cc
    sleigh/pcodeparse.cc
    sleigh/pcoderaw.cc
    sleigh/semantics.cc
    sleigh/sleigh.cc
    sleigh/sleighbase.cc
    sleigh/slghpatexpress.cc
    sleigh/slghpattern.cc
    sleigh/slghsymbol.cc
    sleigh/space.cc
    sleigh/translate.cc
    sleigh/xml.cc)

add_executable(sleigh_builder
    sleigh/filemanage.cc
    sleigh/slgh_compile.cc
    sleigh/slghparse.cc
    sleigh/slghscan.cc
	${sleigh_source})

add_library(sleigh SHARED
	sleigh.cpp
	${sleigh_source})
    
set_target_properties(sleigh PROPERTIES POSITION_INDEPENDENT_CODE ON)

install(FILES sleigh.h DESTINATION include)
install(FILES sleigh_float.h DESTINATION include)
install(TARGETS sleigh DESTINATION lib)
