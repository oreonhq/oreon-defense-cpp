import QtCore
import QtQuick
import QtQuick.Dialogs
import MainUi.Common
import MainUi

import Qt.labs.folderlistmodel

Column {
	id: root
	Row {
		QButton {
			content: "Choose a file"
			onClicked: scannerPick.open()
		}
		QText {
			id: input1
			text: ""
		}
		QFilePicker {
			id: scannerPick
			x: root.width / 2 - width / 2
			y: root.height / 2 - height / 2
			onValueChanged: {
				input1.text = value
			}
		}
	}
	QButton {
		content: "Check File"
		onClicked: {
			let result = Antivirus.checkVirus(input1.text);
			console.warn(`Success: ${result["success"]}`);
			console.warn(`Value: ${result["value"]}`);
			if (result["success"] == 0)
				resultText.text = "No virus found!"
			else if (result["success"] == 1)
				resultText.text = "Virus detected: " + result["value"]
			else
				resultText.text = "Error: " + result["value"]
		}
	}
	QText {
		id: resultText
		text: ""
	}
}
