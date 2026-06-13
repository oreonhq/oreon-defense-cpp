import QtCore
import QtQuick
import QtQuick.Controls
import Qt.labs.folderlistmodel

import QtQml.Models
import QtQuick.Shapes
import Qt5Compat.GraphicalEffects

import MainUi.Common

Popup {
	id: root
    property url value
	implicitWidth: 400
	implicitHeight: 500
    background: Rectangle {
        color: "#3c3c3c"
        radius: 10
    }

	Row {
		height: parent.height
		width: parent.width
        Rectangle {
            width: 100
            height: parent.height
            radius: 10
            color: "#1c1c1c"
            Column {
                anchors.margins: 5
                anchors.fill: parent
                Repeater {
                    model: [StandardPaths.HomeLocation, StandardPaths.DocumentsLocation, StandardPaths.PicturesLocation, StandardPaths.MusicLocation, StandardPaths.DownloadLocation, StandardPaths.DesktopLocation]
                    QButton {
                        required property var modelData
                        content: StandardPaths.displayName(modelData)
                        onClicked: folderModel.folder = StandardPaths.writableLocation(modelData).toString() + "/"
                        width: Math.min(90, implicitWidth)
                        elide: Text.ElideRight
                    }
                }
            }
        }
        Item {
            width: parent.width - 100
            height: parent.height
            Rectangle {
                anchors.fill: parent
                anchors.margins: 10
                width: parent.width - 20
                height: parent.height - 20
                color: "transparent"
                radius: 10
                clip: true
                border {
                    width: 1
                    color: "#1c1c1c"
                }
                ListView {
                    id: listView
                    anchors.fill: parent
                    anchors.centerIn: parent
                    layer.enabled: true
                    layer.effect: OpacityMask {
                        maskSource: Rectangle {
                            radius: 10
                            width: listView.width
                            height: listView.height
                        }
                    }
                    clip: true
                    header: folderModel.folder == "file:///" ? null : btn1

                    
                    Component {
                        id: btn1
                        Item {
                            width: listView.width
                            height: btn2.implicitHeight
                            QButton {
                                id: btn2
                                visible: folderModel.folder != "file:///"
                                onClicked: folderModel.folder = folderModel.folder.toString().slice(0, folderModel.folder.toString().lastIndexOf("/", folderModel.folder.toString().length - 2) + 1)
                                background: Rectangle {
                                    color: parent.hovered ? "#2964ed" : "transparent"
                                }
                                contentItem: Row {
                                    layer.enabled: true
                                    layer.samples: 5
                                    spacing: 5
                                    Shape {
                                        data: ShapePath {
                                            id: path1
                                            strokeColor: "#ffffff"
                                            fillColor: "#ffffff"
                                            startX: btn2.height * 15/64; startY: btn2.height * 3/16;
                                            PathLine { x: btn2.height * 15/64; y: btn2.height * 9/16 }
                                            PathLine { x: btn2.height * 21/32; y: btn2.height * 9/16 }
                                            PathLine { x: btn2.height * 21/32; y: btn2.height * 15/64 }
                                            PathLine { x: btn2.height * 3/8; y: btn2.height * 15/64 }
                                            PathLine { x: btn2.height * 3/8; y: btn2.height * 3/16 }
                                            PathLine { x: btn2.height * 15/64; y: btn2.height * 3/16 }
                                        }
                                    }
                                    Text {
                                        text: "(go to parent directory)"
                                        font.bold: true
                                        color: "#ffffff"
                                    }
                                }
                                width: listView.width - 2
                                anchors.horizontalCenter: parent.horizontalCenter
                            }
                        }
                    }
                    headerPositioning: folderModel.folder == "file:///" ? ListView.OverlayHeader : ListView.InlineHeader
                    model: SortFilterProxyModel {
                        model: FolderListModel {
                            id: folderModel
                            folder: StandardPaths.writableLocation(StandardPaths.HomeLocation).toString() + "/"
                        }
                        sorters: [
                            FunctionSorter {
                                component RoleData: QtObject {
                                    property bool fileIsDir
                                }
                                function sort(lhs: RoleData, rhs: RoleData): int {
                                    return (!lhs.fileIsDir && rhs.fileIsDir) ? 1 : (lhs.fileIsDir === rhs.fileIsDir ? 0 : -1);
                                }
                            },
                            RoleSorter {
                                roleName: "fileName"
                            }
                        ]
                    }
                    delegate: Item {
                        required property string fileName
                        required property bool fileIsDir
                        height: btn.implicitHeight
                        width: listView.width
                        QButton {
                            id: btn
                            background: Rectangle {
                                color: parent.hovered ? "#2964ed" : "transparent"
                            }
                            width: listView.width - 2
                            anchors.horizontalCenter: parent.horizontalCenter
                            onClicked: {
                                if (fileIsDir)
                                    folderModel.folder += fileName + "/"
                                else {
                                    root.value = new URL(folderModel.folder + fileName).pathname
                                    root.close()
                                }
                            }
                            contentItem: Row {
                                spacing: 5
                                layer.enabled: true
                                layer.samples: 5
                                ShapePath {
                                    id: path1
                                    strokeColor: "#ffffff"
                                    fillColor: "#ffffff"
                                    startX: btn.height * 15/64; startY: btn.height * 3/16;
                                    PathLine { x: btn.height * 15/64; y: btn.height * 9/16 }
                                    PathLine { x: btn.height * 21/32; y: btn.height * 9/16 }
                                    PathLine { x: btn.height * 21/32; y: btn.height * 15/64 }
                                    PathLine { x: btn.height * 3/8; y: btn.height * 15/64 }
                                    PathLine { x: btn.height * 3/8; y: btn.height * 3/16 }
                                    PathLine { x: btn.height * 15/64; y: btn.height * 3/16 }
                                }
                                Shape {
                                    data: fileIsDir ? path1 : null
                                }
                                Text {
                                    text: fileName + (fileIsDir ? "/" : "")
                                    color: "#ffffff"
                                    elide: Text.ElideRight
                                }
                            }
                        }
                    }
                }
            }
        }
	}
}
