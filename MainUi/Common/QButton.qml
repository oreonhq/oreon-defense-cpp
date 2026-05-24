import QtQuick
import QtQuick.Controls

Button {
	property var content: "Placeholder"
	leftPadding: 7.5
	rightPadding: 7.5

	background: Rectangle {
		radius: height / 2
		color: parent.hovered ? "#4c4c4c" : "#2c2c2c"
		anchors.fill: parent

		border {
			width: 0.5
			color: "#3c3c3c"
		}
	}

	contentItem: Text {
		color: "#ffffff"
		text: parent.content
	}
}
