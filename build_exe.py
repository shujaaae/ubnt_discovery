"""Build script to create standalone .exe using PyInstaller."""
import PyInstaller.__main__
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
script_path = os.path.join(script_dir, 'ubnt_discovery.py')

PyInstaller.__main__.run([
    script_path,
    '--onefile',           # Single .exe file
    '--windowed',          # No console window (GUI app)
    '--name=UBNT-Discovery',
    '--clean',
    '--noupx',
    '--distpath', os.path.join(script_dir, 'dist'),
    '--workpath', os.path.join(script_dir, 'build'),
    '--specpath', script_dir,
])
