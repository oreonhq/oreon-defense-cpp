import QtQuick

MouseArea {
	id: root
	property bool isSwitched: false

	height: 30
	width: 50

	Rectangle {
		anchors.centerIn: parent
		height: 15
		width: 25
		radius: height / 2

		color: root.isSwitched ? "#00aaff" : "#3c3c3c"
		Behavior on color {
			ColorAnimation { duration: 200 }
		}
	}

	Rectangle {
		id: circle
		width: 20
		height: 20
		anchors.verticalCenter: parent.verticalCenter
		x: 5
		radius: width / 2
		Behavior on x {
			SmoothedAnimation { duration: 200 }
		}
	}

	onClicked: {
		isSwitched = !isSwitched
		circle.x = isSwitched ? width - circle.width - 5 : 5
	}
}
