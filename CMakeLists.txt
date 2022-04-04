cmake_minimum_required(VERSION 3.9)
project(csleigh)

set(sleigh_source
	sleigh/address.cc
	sleigh/context.cc
	sleigh/float.cc
	sleigh/globalcontext.cc
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

add_executable(sleigh
	sleigh/filemanage.cc
	sleigh/slgh_compile.cc
	sleigh/slghparse.cc
	sleigh/slghscan.cc
	${sleigh_source}
)

add_library(csleigh STATIC
	csleigh.cc
	${sleigh_source}
)

set_target_properties(csleigh PROPERTIES POSITION_INDEPENDENT_CODE ON)
