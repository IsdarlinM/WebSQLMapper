@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "PRODUCT=WebSQLMapper"
set "MIN_PYTHON=3.10"
for %%I in ("%~dp0..") do set "SOURCE_ROOT=%%~fI"
if not defined WEBSQLMAPPER_INSTALL_ROOT set "WEBSQLMAPPER_INSTALL_ROOT=%LOCALAPPDATA%\WebSQLMapper"
set "INSTALL_ROOT=%WEBSQLMAPPER_INSTALL_ROOT%"
set "SRC_DIR=%INSTALL_ROOT%\src"
set "VENV_DIR=%INSTALL_ROOT%\venv"
set "BIN_DIR=%INSTALL_ROOT%\bin"
set "WRAPPER=%BIN_DIR%\websqlmapper.cmd"

echo [%PRODUCT%] Checking for an existing Python %MIN_PYTHON% or newer...
call :find_python
if errorlevel 1 (
  echo [%PRODUCT%] No compatible Python installation was found. Attempting installation with winget...
  where winget >nul 2>&1 || goto :no_winget
  winget install --id Python.Python.3.13 --exact --silent --accept-package-agreements --accept-source-agreements
  if errorlevel 1 (
    echo [%PRODUCT%] Python 3.13 installation failed; trying the minimum supported Python 3.10 package...
    winget install --id Python.Python.3.10 --exact --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 goto :python_install_failed
  )
  call :find_python
  if errorlevel 1 goto :python_install_failed
)

where git >nul 2>&1
if errorlevel 1 (
  where winget >nul 2>&1
  if not errorlevel 1 (
    echo [%PRODUCT%] Installing Git for the update command...
    winget install --id Git.Git --exact --silent --accept-package-agreements --accept-source-agreements >nul 2>&1
  ) else (
    echo [%PRODUCT%] WARNING: Git is unavailable. Runtime works, but 'websqlmapper update' will require Git.
  )
)

set "PY_INFO_FILE=%TEMP%\websqlmapper-python-%RANDOM%-%RANDOM%.txt"
"%PY_EXE%" %PY_ARGS% -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" > "%PY_INFO_FILE%" 2>nul
if errorlevel 1 goto :python_info_failed
set /p SELECTED_MM=<"%PY_INFO_FILE%"
"%PY_EXE%" %PY_ARGS% --version > "%PY_INFO_FILE%" 2>&1
if errorlevel 1 goto :python_info_failed
set /p SELECTED_VERSION=<"%PY_INFO_FILE%"
del /q "%PY_INFO_FILE%" >nul 2>&1
echo [%PRODUCT%] Using existing compatible interpreter: %SELECTED_VERSION% [%PY_DISPLAY%].
if exist "%INSTALL_ROOT%\src.new" rmdir /s /q "%INSTALL_ROOT%\src.new"
if not exist "%INSTALL_ROOT%" mkdir "%INSTALL_ROOT%"
mkdir "%INSTALL_ROOT%\src.new" >nul 2>&1
robocopy "%SOURCE_ROOT%" "%INSTALL_ROOT%\src.new" /E /XD .venv .pytest_cache __pycache__ /XF *.pyc >nul
if errorlevel 8 goto :copy_failed
if exist "%SRC_DIR%" rmdir /s /q "%SRC_DIR%"
move "%INSTALL_ROOT%\src.new" "%SRC_DIR%" >nul || goto :copy_failed

if exist "%VENV_DIR%" rmdir /s /q "%VENV_DIR%"
"%PY_EXE%" %PY_ARGS% -m venv "%VENV_DIR%"
if errorlevel 1 goto :venv_failed
"%VENV_DIR%\Scripts\python.exe" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" > "%PY_INFO_FILE%" 2>nul
if errorlevel 1 goto :venv_failed
set /p VENV_MM=<"%PY_INFO_FILE%"
del /q "%PY_INFO_FILE%" >nul 2>&1
if not "%VENV_MM%"=="%SELECTED_MM%" goto :venv_version_mismatch
echo [%PRODUCT%] Virtual environment uses Python %VENV_MM%; dependencies will be installed into this interpreter.

"%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel
if errorlevel 1 echo [%PRODUCT%] WARNING: packaging-tool upgrade failed; continuing with available versions.
"%VENV_DIR%\Scripts\python.exe" -m pip install -e "%SRC_DIR%[socks]"
if errorlevel 1 (
  echo [%PRODUCT%] WARNING: optional SOCKS dependency installation failed; installing core support instead.
  "%VENV_DIR%\Scripts\python.exe" -m pip install -e "%SRC_DIR%"
  if errorlevel 1 goto :pip_failed
)

if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
> "%WRAPPER%" echo @echo off
>> "%WRAPPER%" echo "%VENV_DIR%\Scripts\python.exe" -m websqlmapper %%*

if not "%WEBSQLMAPPER_SKIP_PATH%"=="1" call :set_environment
"%WRAPPER%" --version >nul 2>&1
if errorlevel 1 goto :verify_failed

"%VENV_DIR%\Scripts\python.exe" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" > "%PY_INFO_FILE%" 2>nul
if errorlevel 1 goto :verify_failed
set /p INSTALLED_MM=<"%PY_INFO_FILE%"
del /q "%PY_INFO_FILE%" >nul 2>&1
echo [%PRODUCT%] Installation verified with Python %INSTALLED_MM%.
echo [%PRODUCT%] All Python dependencies are installed in: %VENV_DIR%
echo [%PRODUCT%] Command: websqlmapper
echo [%PRODUCT%] Home: %INSTALL_ROOT%
echo [%PRODUCT%] PATH entry: %BIN_DIR%
echo [%PRODUCT%] Open a new Command Prompt so the updated user PATH is loaded.
exit /b 0

:find_python
set "PY_EXE="
set "PY_ARGS="
set "PY_DISPLAY="
rem Prefer the user's current/default interpreter when it already satisfies >=3.10.
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 (
  set "PY_EXE=python"
  set "PY_ARGS="
  set "PY_DISPLAY=python"
  exit /b 0
)
python3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 (
  set "PY_EXE=python3"
  set "PY_ARGS="
  set "PY_DISPLAY=python3"
  exit /b 0
)
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if not errorlevel 1 (
  set "PY_EXE=py"
  set "PY_ARGS=-3"
  set "PY_DISPLAY=py -3"
  exit /b 0
)
if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" call :select_local_python "%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
if defined PY_EXE exit /b 0
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" call :select_local_python "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if defined PY_EXE exit /b 0
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" call :select_local_python "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if defined PY_EXE exit /b 0
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" call :select_local_python "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
if defined PY_EXE exit /b 0
if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" call :select_local_python "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
if defined PY_EXE exit /b 0
exit /b 1

:select_local_python
"%~1" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if errorlevel 1 exit /b 0
set "PY_EXE=%~1"
set "PY_ARGS="
set "PY_DISPLAY=%~1"
exit /b 0

:set_environment
setx WEBSQLMAPPER_HOME "%INSTALL_ROOT%" >nul
set "USER_PATH="
for /f "tokens=2,*" %%A in ('reg query HKCU\Environment /v Path 2^>nul ^| findstr /I "Path"') do set "USER_PATH=%%B"
if not defined USER_PATH (
  reg add HKCU\Environment /v Path /t REG_EXPAND_SZ /d "%BIN_DIR%" /f >nul
  exit /b 0
)
echo ;%USER_PATH%; | findstr /I /C:";%BIN_DIR%;" >nul
if errorlevel 1 reg add HKCU\Environment /v Path /t REG_EXPAND_SZ /d "%USER_PATH%;%BIN_DIR%" /f >nul
exit /b 0

:python_info_failed
if defined PY_INFO_FILE del /q "%PY_INFO_FILE%" >nul 2>&1
echo [%PRODUCT%] ERROR: Failed to read the selected Python version. 1>&2
exit /b 1
:no_winget
echo [%PRODUCT%] ERROR: Python %MIN_PYTHON%+ is missing and winget is unavailable. Install Python from python.org, then rerun this .cmd installer. 1>&2
exit /b 1
:python_install_failed
echo [%PRODUCT%] ERROR: Python installation failed or no Python %MIN_PYTHON%+ interpreter was discoverable after winget completed. 1>&2
exit /b 1
:copy_failed
echo [%PRODUCT%] ERROR: Failed to copy project files into %SRC_DIR%. 1>&2
exit /b 1
:venv_failed
echo [%PRODUCT%] ERROR: Failed to create the isolated Python environment using %PY_DISPLAY%. 1>&2
exit /b 1
:venv_version_mismatch
echo [%PRODUCT%] ERROR: The venv Python version %VENV_MM% does not match selected Python %SELECTED_MM%. 1>&2
exit /b 1
:pip_failed
echo [%PRODUCT%] ERROR: Failed to install Python dependencies/package into Python %SELECTED_MM%. 1>&2
exit /b 1
:verify_failed
echo [%PRODUCT%] ERROR: Installation completed but the websqlmapper command verification failed. 1>&2
exit /b 1
