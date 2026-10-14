cmake_minimum_required(VERSION 3.16)
project(oreon-defense VERSION 1.0.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

option(OREON_BUILD_TESTS "Build unit tests" ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets DBus Network)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(YAML_CPP REQUIRED yaml-cpp)
find_package(nlohmann_json QUIET)

include_directories(
  ${CMAKE_SOURCE_DIR}/common/include
  ${CMAKE_SOURCE_DIR}/daemon/include
  ${CMAKE_SOURCE_DIR}/gui/include
  ${CMAKE_SOURCE_DIR}/gui
  ${YAML_CPP_INCLUDE_DIRS}
)

if(nlohmann_json_FOUND)
  # cmake package available
elseif(EXISTS "/usr/include/nlohmann/json.hpp")
  # fedora/oreon json-devel
else()
  message(FATAL_ERROR "nlohmann/json.hpp not found. Install json-devel")
endif()

set(DAEMON_SOURCES
  daemon/src/main.cpp
  daemon/src/Daemon.cpp
  daemon/src/Config.cpp
  daemon/src/EventLog.cpp
  daemon/src/RuleEngine.cpp
  daemon/src/Quarantine.cpp
  daemon/src/FileMonitor.cpp
  daemon/src/ProcessMonitor.cpp
  daemon/src/NetworkMonitor.cpp
  daemon/src/Scanner.cpp
  daemon/src/SocketServer.cpp
)

add_executable(oreon-defense-daemon ${DAEMON_SOURCES})
target_link_libraries(oreon-defense-daemon
  PRIVATE
  OpenSSL::Crypto
  ${YAML_CPP_LIBRARIES}
  pthread
)
target_compile_options(oreon-defense-daemon PRIVATE ${YAML_CPP_CFLAGS_OTHER})

set(GUI_SOURCES
  gui/src/main.cpp
  gui/src/MainWindow.cpp
  gui/src/DaemonClient.cpp
  gui/include/MainWindow.hpp
  gui/include/DaemonClient.hpp
  gui/include/TrayIcon.hpp
  gui/include/Theme.hpp
  gui/pages/HomePage.hpp
  gui/pages/ScansPage.hpp
  gui/pages/ThreatsPage.hpp
  gui/pages/HistoryPage.hpp
  gui/pages/SettingsPage.hpp
)

add_executable(oreon-defense ${GUI_SOURCES})
target_link_libraries(oreon-defense
  PRIVATE
  Qt6::Widgets
  Qt6::DBus
  Qt6::Network
)

include(GNUInstallDirs)

install(TARGETS oreon-defense oreon-defense-daemon
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(FILES data/oreon-defense.desktop
  DESTINATION ${CMAKE_INSTALL_DATADIR}/applications)

install(FILES data/oreon-defense-autostart.desktop
  DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/xdg/autostart)

install(FILES data/rules/starter-rules.yaml
  DESTINATION ${CMAKE_INSTALL_DATADIR}/oreon-defense/rules)

install(DIRECTORY data/icons/hicolor
  DESTINATION ${CMAKE_INSTALL_DATADIR}/icons)

install(FILES systemd/oreon-defense.service
              systemd/oreon-defense-scan.service
              systemd/oreon-defense-scan.timer
  DESTINATION lib/systemd/system)

install(FILES polkit/org.oreon.defense.policy
  DESTINATION ${CMAKE_INSTALL_DATADIR}/polkit-1/actions)

install(FILES dbus/org.oreon.Defense1.conf
  DESTINATION ${CMAKE_INSTALL_DATADIR}/dbus-1/system.d)

install(PROGRAMS scripts/trigger-scan.sh
                  scripts/test_installed_detection.sh
  DESTINATION libexec/oreon-defense)

install(DIRECTORY tests/samples/
  DESTINATION ${CMAKE_INSTALL_DATADIR}/oreon-defense/samples)

install(FILES config/config.json.example
  DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/oreon-defense
  RENAME config.json)

if(OREON_BUILD_TESTS)
  enable_testing()
  add_executable(test_rules tests/test_rules.cpp daemon/src/RuleEngine.cpp)
  target_link_libraries(test_rules PRIVATE OpenSSL::Crypto ${YAML_CPP_LIBRARIES} pthread)
  target_compile_options(test_rules PRIVATE ${YAML_CPP_CFLAGS_OTHER})
  add_test(NAME test_rules COMMAND test_rules
    ${CMAKE_SOURCE_DIR}/data/rules/starter-rules.yaml
    ${CMAKE_SOURCE_DIR}/tests/samples)

  add_executable(test_quarantine tests/test_quarantine.cpp daemon/src/Quarantine.cpp)
  target_link_libraries(test_quarantine PRIVATE OpenSSL::Crypto pthread)
  add_test(NAME test_quarantine COMMAND test_quarantine)
endif()
