import QtQuick
import QtQuick.Controls

Button {
	property var content: "Placeholder"
	leftPadding: 7.5
	rightPadding: 7.5
	property var elide: Text.ElideNone
	property real radius: height / 2
	property string bgcolor: hovered ? "#4c4c4c" : "#2c2c2c"

	background: Rectangle {
		radius: parent.radius
		color: parent.bgcolor
		anchors.fill: parent

		border {
			width: 0.5
			color: "#3c3c3c"
		}
	}

	contentItem: Text {
		color: "#ffffff"
		text: parent.content
		elide: parent.elide
	}
}
