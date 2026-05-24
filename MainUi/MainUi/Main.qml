import QtQuick
import QtQuick.Window
import QtQuick.Controls

Window {
	width: 400
	height: 300
	visible: true
	title: qsTr("Hello world!")
	color: "#1c1c1c"

	Rectangle {
		id: pageSelector
		anchors.left: parent.left
		anchors.leftMargin: 10
		anchors.top: parent.top
		anchors.topMargin: 10

		radius: 10
		height: parent.height - 20
		width: 250
		color: "#0c0c0c"

		ListView {
            anchors.left: parent.left
            anchors.leftMargin: 10
            anchors.top: parent.top
            anchors.topMargin: 10

            ScrollBar.vertical: ScrollBar {
                width: 10
                contentItem: Rectangle {
                    color: (parent.hovered || parent.pressed) ? "#7c7c7c" : "#995c5c5c"
                    radius: width / 2
                }
            }

            spacing: 5
            height: parent.height - 20
            width: parent.width - 15
            contentWidth: width - 15
            clip: true

            model: loaders.children.filter(x => !(x instanceof Repeater))

            delegate: Button {
            	id: btn
            	width: parent.width
            	height: 40

            	required property var modelData

            	background: Rectangle {
            		radius: 10
            		color: modelData.active ? (parent.hovered ? "#1c1c1c" : "#0c0c0c") :(parent.hovered ? "#3c3c3c" : "#1c1c1c")
					border {
                        width: 1
                        color: "#1c1c20"
                    }
            	}
	            contentItem: Row {
	                spacing: 10
	                Text {
	                    anchors.verticalCenter: parent.verticalCenter
	                    text: "[icon]"
	                    color: "#fff"
	                }
	                Text {
	                    anchors.verticalCenter: parent.verticalCenter
	                    color: "#fff"
	                    text: modelData.name
	                }
	            }

	            onClicked: {
	                for (let i of loaders.children.filter(x => !(x instanceof Repeater)))
	                    i.active = false;
	                modelData.active = true;
	            }
	        }
        }
	}
	Item {
		id: loaders
		anchors.left: pageSelector.right
		anchors.leftMargin: 10
		anchors.top: parent.top
		anchors.topMargin: 10

		width: parent.width - pageSelector.width - 40
		height: parent.height - 20
		
		Repeater {
			model: ["antivirus.qml", "firewall.qml"]

			Loader {
				width: loaders.width
				height: loaders.height
				required property string modelData
				property string name: modelData.split(".")[0].replace("_", " ").replace(/(^.|(?: ).)/g, (w) => w.toUpperCase())
				active: false

				sourceComponent: SettingsPage {
					width: parent.width
					height: parent.height
					Item {
						anchors.left: parent.left
						anchors.leftMargin: 10
						anchors.top: parent.top
						anchors.topMargin: 10
						width: parent.width
						height: parent.height

						Loader {
							width: parent.width - 20
							height: parent.height - 20
							active: true
							source: "pages/" + modelData
						}
					}
				}
			}
		}
	}
}
