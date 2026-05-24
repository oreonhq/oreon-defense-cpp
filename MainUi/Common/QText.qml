import QtQuick

Row {
	id: root

	height: 30
	required property string text
	property bool bold: false
	property int fontSize: 15

	Text {
		anchors.verticalCenter: parent.verticalCenter
		color: "#ffffff"
		text: parent.text
		font {
			bold: bold
			pixelSize: root.fontSize
		}
	}
}
