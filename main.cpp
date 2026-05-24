#include <QtCore>
#include <QtGui>
#include <QtWidgets>
#include <iostream>

int main(int argc, char** argv) {
	QApplication app(argc, argv);
	std::cout << "App initialized" << std::endl;

	QMainWindow win;
	win.resize(300, 400);
	win.setVisible(true);
	
	std::cout << "About to execute" << std::endl;
	return app.exec();
}
