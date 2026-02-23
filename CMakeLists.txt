cmake_minimum_required (VERSION 3.10)

if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
endif()

project ("ImpXproto")

if (MSVC)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT 
        "$<IF:$<CONFIG:Debug,RelWithDebInfo>,EditAndContinue,ProgramDatabase>")
endif()

if (ANDROID)
    message(STATUS "Building for Android. ABI: ${ANDROID_ABI}, Platform: ${ANDROID_PLATFORM}")
endif()

if (CMAKE_COMPILER_IS_GNUCXX)
    add_compile_options(-Wall -Wextra)
endif()

add_subdirectory ("ImpXproto")
