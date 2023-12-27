# -*- coding: utf-8 -*-
#
# Run the build process by running the command 'python win_setup.py bdist_msi'
#

import sys
from cx_Freeze import setup, Executable
import os
import configparser
import os.path

PYTHON_INSTALL_DIR = os.path.dirname(os.path.dirname(os.__file__))
os.environ['TCL_LIBRARY'] = os.path.join(PYTHON_INSTALL_DIR, 'tcl', 'tcl8.6')
os.environ['TK_LIBRARY'] = os.path.join(PYTHON_INSTALL_DIR, 'tcl', 'tk8.6')

param_name = "help/version.cfg"
default_count = 0
config_count = 0
cfg = configparser.ConfigParser()
cfg.read(param_name)
par=dict(cfg.items("DEFAULT"))
for p in par:
  par[p]=par[p].split("#",1)[0].strip() # To get rid of inline comments
globals().update(par)

includes = ['sqlite3', 'idna', 'idna.idnadata','pandas','xlsxwriter']

base = None
if sys.platform == 'win32':
  base = 'Win32GUI'

include_files = [os.path.join(PYTHON_INSTALL_DIR, 'DLLs', 'tk86t.dll'),
                os.path.join(PYTHON_INSTALL_DIR, 'DLLs', 'tcl86t.dll'),
                'sqlite3.dll',
                'db/', 'help/', 'images/','schema/', 'reports/','app.ico']
# http://msdn.microsoft.com/en-us/library/windows/desktop/aa371847(v=vs.85).aspx
shortcut_table = [
  ("DesktopShortcut",  # Shortcut
    "DesktopFolder",  # Directory_
    title,  # Name
    "TARGETDIR",  # Component_
    "[TARGETDIR]main.exe",  # Target
    None,  # Arguments
    None,  # Description
    None,  # Hotkey
    None,  # Icon
    None,  # IconIndex
    None,  # ShowCmd
    'TARGETDIR'  # WkDir
    )
]

executables = [
  Executable('main.py', base=base, icon="app.ico", )
]
# Now create the table dictionary
msi_data = {"Shortcut": shortcut_table}
# Change some default MSI options and specify the use of the above defined tables
bdist_msi_options = {'data': msi_data}
setup(name=title,
  version=version,
  description=title,
  options={"build_exe": {"includes": includes, "include_files": include_files}, "bdist_msi": bdist_msi_options},
  executables=executables,
)
