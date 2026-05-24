import QtQuick
import QtQuick.Window
import QtQuick.Controls

Window {
	width: 400
	height: 300
	visible: true
	title: qsTr("Hello world!")
	color: "#0c0c0c"

	Row {
		Column {
			Button {
				contentItem: Text { text: "firewall" }
			}
		}
	}
}
