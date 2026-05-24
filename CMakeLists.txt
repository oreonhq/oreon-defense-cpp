cmake_minimum_required(VERSION 3.14)

project(oreon-defense VERSION 0.1 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 COMPONENTS Core Quick Widgets Qml REQUIRED)

set(PROJECT_SOURCES
        main.cpp
        qml.qrc
)

qt_add_executable(oreon-defense
    MANUAL_FINALIZATION
    ${PROJECT_SOURCES}
)
add_subdirectory(MainUi/Common)
qt_add_qml_module(oreon-defense
	URI MainUi
	VERSION 1.0
	QML_FILES
		MainUi/Main.qml
		MainUi/SettingsPage.qml
		MainUi/pages/firewall.qml
		MainUi/pages/antivirus.qml
	DEPENDENCIES TARGET common
)

target_compile_definitions(oreon-defense
  PRIVATE $<$<OR:$<CONFIG:Debug>,$<CONFIG:RelWithDebInfo>>:QT_QML_DEBUG>)
target_link_libraries(oreon-defense
  PRIVATE Qt6::Core Qt6::Quick Qt6::Widgets Qt6::Qml)


qt_import_qml_plugins(oreon-defense)
qt_finalize_executable(oreon-defense)
