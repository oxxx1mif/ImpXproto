add_executable (ImpXproto "ImpXproto.cpp" "ImpXproto.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ImpXproto PROPERTY CXX_STANDARD 20)
endif()
