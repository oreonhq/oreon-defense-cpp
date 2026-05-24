import QtQuick
import QtQuick.Controls
import "." as C

Row {
	id: root
	property string label: "Value: "
	property var model: ["true", "false"]

	function value() {
		return combo.currentValue != "N/A" ? combo.currentValue : null
	}

	function reset() {
		combo.currentValue = "N/A"
	}

	C.QText {
		text: root.label
	}
	ComboBox {
		id: combo
		model: ["N/A", ...root.model]
		background: Rectangle {
			implicitWidth: 120
			color: combo.hovered ? "#2c2c2c" : "#0c0c0c"
			radius: height / 4
		}
		delegate: ItemDelegate {
			width: combo.width
			contentItem: Text {
				text: modelData
				color: "#ffffff"
			}
			background: Rectangle {
				radius: 10
				color: combo.highlightedIndex == index ? "#3c3c3c" : "transparent"
			}
		}
		popup: Popup {
			width: combo.width
			implicitHeight: contentItem.implicitHeight

			contentItem: ListView {
				id: lv
				implicitHeight: contentHeight
				model: combo.delegateModel
				clip: true

				ScrollIndicator.vertical: ScrollIndicator { }
			}

			padding: 0

			background: Rectangle {
				color: "#0c0c0c"
				radius: 10
				border {
					width: 1
					color: "#1c1c1c"
				}
			}
		}
	}
}
