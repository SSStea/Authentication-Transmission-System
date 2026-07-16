#include <QApplication>
#include <QMainWindow>

int main(int nArgc, char* arrArgv[])
{
    QApplication appApplication(nArgc, arrArgv);
    QMainWindow  wndMain;

    wndMain.setWindowTitle(QStringLiteral("TESLA UAV Monitor"));
    wndMain.resize(960, 640);
    wndMain.show();

    return appApplication.exec();
}
