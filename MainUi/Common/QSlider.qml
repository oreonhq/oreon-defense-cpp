import QtQuick
import QtQuick.Controls

Slider {
    id: root
    
    from: 0
    to: 100
    snapMode: Slider.SnapOnRelease
    stepSize: 1.0
    height: 20
    handle: Item {
    	enabled: false
        x: root.visualPosition * root.width - 10
        Rectangle {
            implicitWidth: 20
            implicitHeight: 20
            radius: 1000
            MouseArea {
                id: handleMouse
                anchors.fill: parent
                hoverEnabled: true
            }
        }
        Rectangle {
            y: -30
            visible: root.hovered || root.pressed
            width: children[0].width + 10
            height: children[0].height
            radius: height / 4
            color: "#050505"
            border {
            	width: 1
            	color: "#1c1c1c"
            }
            Text {
           		anchors.verticalCenter: parent.verticalCenter
           		anchors.horizontalCenter: parent.horizontalCenter
            	text: `${Math.floor(root.value)}%`
            	color: "#ffffff"
            }
        }
    }
    background: Rectangle {
    	anchors.verticalCenter: parent.verticalCenter
        implicitWidth: 200
        implicitHeight: 15
        color: "#0c0c0c"
        radius: height / 2

        Rectangle {
            width: handle.x < 0 ? 0 : root.visualPosition * parent.width + 10
            height: parent.height
            color: "#3399ff"
            radius: height / 2
        }
    }
}


