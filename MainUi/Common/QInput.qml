import QtQuick
import QtQuick.Controls

import "." as C

Row {
	id: root

	function value() {
		return text.length > 0 ? `"${text.replace(/"/g, '\\"')}"` : null
	}
	function reset() {
		text = ""
	}

    property string bgcolor: "#0c0c0c"
    property string fgcolor: "#ffffff"
    property string pltext: "Enter a value..."

    property alias text: field.text

   	property int bgradius: field.height / 4

   	property bool bold: true
   	property string label: "Value: "

	height: 30

	C.QText {
		text: root.label
	}

	TextField {
		id: field

		anchors.verticalCenter: parent.verticalCenter

		placeholderText: root.pltext

	    verticalAlignment: Text.AlignVCenter
	   	leftPadding: 5
	   	rightPadding: 5

	    font {
	        bold: root.bold
	    }

	    background: Rectangle {
	        color: root.bgcolor
	        radius: root.bgradius
	    }
	}
}
