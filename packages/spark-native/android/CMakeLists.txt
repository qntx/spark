project(SparkNative)
cmake_minimum_required(VERSION 3.9.0)

set(PACKAGE_NAME SparkNative)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 20)

# The C++ hybrid is the only thing we compile here: libqntx_spark.so is a
# prebuilt spark-ffi cdylib per ABI under src/main/jniLibs (built by
# `bun run build:native`), packaged into the AAR and linked for its qs_* symbols.
file(GLOB shared_files RELATIVE ${CMAKE_SOURCE_DIR}
     "../cpp/**.cpp" "src/main/cpp/**.cpp"
)

add_library(${PACKAGE_NAME} SHARED ${shared_files})

# Add Nitrogen specs :)
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/SparkNative+autolinking.cmake)

add_library(qntx_spark SHARED IMPORTED)
set_target_properties(
        qntx_spark
        PROPERTIES IMPORTED_LOCATION
        ${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libqntx_spark.so
)

include_directories(
        "../cpp"
        "../include"
)

find_library(LOG_LIB log)

target_link_libraries(
        ${PACKAGE_NAME}
        qntx_spark
        ${LOG_LIB}
        android
)
