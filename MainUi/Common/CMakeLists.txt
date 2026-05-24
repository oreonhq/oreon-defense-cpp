cmake_minimum_required(VERSION 3.16)
project(common LANGUAGES CXX)

find_package(Qt6 REQUIRED COMPONENTS Quick)
qt_standard_project_setup(REQUIRES 6.8)

qt_add_qml_module(common
    URI MainUi.Common
    QML_FILES
        QButton.qml
        QCombo.qml
        QInput.qml
        QSlider.qml
        QSwitch.qml
        QText.qml)
