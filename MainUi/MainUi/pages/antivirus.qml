import QtQuick
import MainUi.Common
import MainUi

Column {
	Column {
		QInput {
			id: input1
			label: "File: "
			pltext: "Type the name of a file..."
		}
		QButton {
			content: "Check File"
			onClicked: {
				let result = Antivirus.checkVirus(input1.text);
				console.warn(`Success: ${result["success"]}`);
				console.warn(`Value: ${result["value"]}`);
			}
		}
	}
}
