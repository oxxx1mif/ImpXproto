add_executable(ImpXproto "ImpXproto.cpp" "ImpXproto.h")

set_target_properties(ImpXproto PROPERTIES 
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

if(ANDROID)
    find_library(log-lib log)
    target_link_libraries(ImpXproto ${log-lib})
endif()

if(UNIX AND NOT APPLE AND NOT ANDROID)
    find_package(Threads REQUIRED)
    target_link_libraries(ImpXproto PRIVATE Threads::Threads)
    
    set_target_properties(ImpXproto PROPERTIES INSTALL_RPATH "$ORIGIN")
endif()
