cmake_minimum_required(VERSION 3.16)
project(oreon-defense VERSION 1.0.16 LANGUAGES CXX)

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
pkg_check_modules(CLAMAV REQUIRED libclamav)
pkg_check_modules(CURL REQUIRED libcurl)

add_compile_definitions(OREON_VERSION="${PROJECT_VERSION}")
find_package(nlohmann_json QUIET)

include_directories(
  ${CMAKE_SOURCE_DIR}/common/include
  ${CMAKE_SOURCE_DIR}/daemon/include
  ${CMAKE_SOURCE_DIR}/gui/include
  ${CMAKE_SOURCE_DIR}/gui
  ${YAML_CPP_INCLUDE_DIRS}
  ${CLAMAV_INCLUDE_DIRS}
  ${CURL_INCLUDE_DIRS}
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
  daemon/src/SystemTrust.cpp
  daemon/src/ChangeAssess.cpp
  daemon/src/WriteTracker.cpp
  daemon/src/Quarantine.cpp
  daemon/src/FileMonitor.cpp
  daemon/src/ProcessMonitor.cpp
  daemon/src/CmdlineHeuristics.cpp
  daemon/src/NetworkMonitor.cpp
  daemon/src/Scanner.cpp
  daemon/src/SocketServer.cpp
  daemon/src/ClamEngine.cpp
  daemon/src/OnAccessMonitor.cpp
  daemon/src/NetBlocker.cpp
  daemon/src/RuleUpdater.cpp
  daemon/src/GuardMonitor.cpp
  daemon/src/Signature.cpp
  daemon/src/PeerAuth.cpp
)

add_executable(oreon-defense-daemon ${DAEMON_SOURCES})
target_link_directories(oreon-defense-daemon PRIVATE ${CLAMAV_LIBRARY_DIRS} ${CURL_LIBRARY_DIRS})
target_link_libraries(oreon-defense-daemon
  PRIVATE
  OpenSSL::Crypto
  ${YAML_CPP_LIBRARIES}
  ${CLAMAV_LIBRARIES}
  ${CURL_LIBRARIES}
  pthread
)
target_compile_options(oreon-defense-daemon PRIVATE ${YAML_CPP_CFLAGS_OTHER} ${CLAMAV_CFLAGS_OTHER})

set(GUI_SOURCES
  gui/src/main.cpp
  gui/src/MainWindow.cpp
  gui/src/DaemonClient.cpp
  gui/src/Notifier.cpp
  gui/src/AlertBatcher.cpp
  gui/include/Notifier.hpp
  gui/include/AlertBatcher.hpp
  gui/include/MainWindow.hpp
  gui/include/DaemonClient.hpp
  gui/include/TrayIcon.hpp
  gui/include/Theme.hpp
  gui/pages/HomePage.hpp
  gui/pages/ScansPage.hpp
  gui/pages/ThreatsPage.hpp
  gui/pages/HistoryPage.hpp
  gui/pages/SettingsPage.hpp
  gui/icons/icons.qrc
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

install(FILES data/keys/od-rules-ed25519.pub
  DESTINATION ${CMAKE_INSTALL_DATADIR}/oreon-defense/keys)

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
                  scripts/verify_detection.sh
  DESTINATION libexec/oreon-defense)

install(DIRECTORY tests/samples/
  DESTINATION ${CMAKE_INSTALL_DATADIR}/oreon-defense/samples)

install(FILES config/config.json.example
  DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/oreon-defense
  RENAME config.json)

if(OREON_BUILD_TESTS)
  enable_testing()
  add_executable(test_rules tests/test_rules.cpp daemon/src/RuleEngine.cpp daemon/src/SystemTrust.cpp)
  target_link_libraries(test_rules PRIVATE OpenSSL::Crypto ${YAML_CPP_LIBRARIES} pthread)
  target_compile_options(test_rules PRIVATE ${YAML_CPP_CFLAGS_OTHER})
  add_test(NAME test_rules COMMAND test_rules
    ${CMAKE_SOURCE_DIR}/data/rules/starter-rules.yaml
    ${CMAKE_SOURCE_DIR}/tests/samples)

  add_executable(test_heuristics tests/test_heuristics.cpp daemon/src/RuleEngine.cpp
    daemon/src/SystemTrust.cpp)
  target_link_libraries(test_heuristics PRIVATE OpenSSL::Crypto ${YAML_CPP_LIBRARIES} pthread)
  target_compile_options(test_heuristics PRIVATE ${YAML_CPP_CFLAGS_OTHER})
  add_test(NAME test_heuristics COMMAND test_heuristics
    ${CMAKE_SOURCE_DIR}/data/rules/starter-rules.yaml
    ${CMAKE_SOURCE_DIR}/tests/samples)
  set_tests_properties(test_heuristics PROPERTIES SKIP_RETURN_CODE 77)

  add_executable(test_alerts tests/test_alerts.cpp gui/src/AlertBatcher.cpp)
  target_link_libraries(test_alerts PRIVATE Qt6::Core)
  add_test(NAME test_alerts COMMAND test_alerts)

  add_executable(test_quarantine tests/test_quarantine.cpp daemon/src/Quarantine.cpp)
  target_link_libraries(test_quarantine PRIVATE OpenSSL::Crypto pthread)
  add_test(NAME test_quarantine COMMAND test_quarantine)

  add_executable(test_feed tests/test_feed.cpp daemon/src/RuleEngine.cpp
    daemon/src/SystemTrust.cpp daemon/src/Signature.cpp daemon/src/NetBlocker.cpp)
  target_link_libraries(test_feed PRIVATE OpenSSL::Crypto ${YAML_CPP_LIBRARIES} pthread)
  target_compile_options(test_feed PRIVATE ${YAML_CPP_CFLAGS_OTHER})
  add_test(NAME test_feed COMMAND test_feed
    ${CMAKE_SOURCE_DIR}/data/keys/od-rules-ed25519.pub
    ${CMAKE_SOURCE_DIR}/rules-feed)

  add_executable(test_clamav tests/test_clamav.cpp daemon/src/ClamEngine.cpp)
  target_link_directories(test_clamav PRIVATE ${CLAMAV_LIBRARY_DIRS})
  target_link_libraries(test_clamav PRIVATE ${CLAMAV_LIBRARIES} pthread)
  add_test(NAME test_clamav COMMAND test_clamav
    ${CMAKE_SOURCE_DIR}/tests/samples/eicar.com /var/lib/clamav)
  set_tests_properties(test_clamav PROPERTIES SKIP_RETURN_CODE 77)

  add_executable(test_guard tests/test_guard.cpp)
  add_test(NAME test_guard COMMAND test_guard)

  add_executable(test_tray tests/test_tray.cpp)
  target_include_directories(test_tray PRIVATE gui/include gui)
  target_link_libraries(test_tray PRIVATE Qt6::Core)
  add_test(NAME test_tray COMMAND test_tray)

  add_executable(test_scancount tests/test_scancount.cpp)
  target_include_directories(test_scancount PRIVATE gui/include gui)
  target_link_libraries(test_scancount PRIVATE Qt6::Core)
  add_test(NAME test_scancount COMMAND test_scancount)

  add_executable(test_proctrust tests/test_proctrust.cpp daemon/src/SystemTrust.cpp)
  target_link_libraries(test_proctrust PRIVATE OpenSSL::Crypto pthread)
  add_test(NAME test_proctrust COMMAND test_proctrust)
  set_tests_properties(test_proctrust PROPERTIES SKIP_RETURN_CODE 77)

  add_executable(test_attribution tests/test_attribution.cpp daemon/src/SystemTrust.cpp
    daemon/src/ChangeAssess.cpp daemon/src/WriteTracker.cpp)
  target_link_libraries(test_attribution PRIVATE OpenSSL::Crypto pthread)
  add_test(NAME test_attribution COMMAND test_attribution)
  set_tests_properties(test_attribution PROPERTIES SKIP_RETURN_CODE 77)
  add_executable(test_realworld tests/test_realworld.cpp daemon/src/SystemTrust.cpp
    daemon/src/CmdlineHeuristics.cpp)
  target_include_directories(test_realworld PRIVATE daemon/include common/include)
  target_link_libraries(test_realworld PRIVATE OpenSSL::Crypto pthread)
  add_test(NAME test_realworld COMMAND test_realworld)
  set_tests_properties(test_realworld PROPERTIES SKIP_RETURN_CODE 77)

  add_executable(test_threatstate tests/test_threatstate.cpp)
  add_test(NAME test_threatstate COMMAND test_threatstate)

  add_executable(test_notify tests/test_notify.cpp)
  target_include_directories(test_notify PRIVATE gui/include gui)
  target_link_libraries(test_notify PRIVATE Qt6::Core)
  add_test(NAME test_notify COMMAND test_notify)

  add_executable(test_delete_auth tests/test_delete_auth.cpp daemon/src/PeerAuth.cpp)
  target_link_libraries(test_delete_auth PRIVATE pthread)
  add_test(NAME test_delete_auth COMMAND test_delete_auth)
endif()
