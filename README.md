# Phone Report Tool
A PythonTk GUI program to pull phone reports from Cisco Unified Communications Manager (CUCM).

![Phone Report Tool](/screenshot/screenshot.png?raw=true "Main Window")

Tested using Python 3.11

### Clean up directory (MAC OS X)
* rm -rf build dist myenv

### Clean up directory (Windows)
* rmdir /s /q build dist

### Create Virtual Enviroment with pynenv (MAC OS X)
```
python3 -m venv myenv
source myenv/bin/activate
python3 -m pip install --upgrade pip
```

### Create Virtual Enviroment with pynenv (Windows)
* python -m venv myenv
* .\myenv\Scripts\activate
* python -m pip install --upgrade pip

### Update pyvenv.cfg if not using requirements.txt (MAC OS X)
* nano myenv/pyvenv.cfg
* include-system-site-packages = true
* Control-O, Control-X, y

### Install package requirements
* pip3 install -r requirements.txt

### Compile with pyinstaller (MAC OS X)
* pyinstaller main.spec --noconfirm

### Compile with cx_freeze (Windows)
* python win_setup.py bdist_msi

### Create DMG (MAC OS X)
```
cp dmgpackage.command dist/dmgpackage.command
cp background.png dist/background.png
cd dist
chmod +x dmgpackage.command
sh dmgpackage.command
rm -rf ./*.app
rm -rf ./*.png
rm -rf ./*.command
rm -rf Phone\ Report\ Tool
```

### Testing app (MAC OS X)
* ./dist/Phone\ Report\ Tool.app/Contents/MacOS/Phone\ Report\ Tool

### Giving Back

If you would like to support my work and the time I put in creating the code, you can click the image below to get me a coffee. I would really appreciate it (but is not required).

<a href="https://www.buymeacoffee.com/automatebldrs" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>