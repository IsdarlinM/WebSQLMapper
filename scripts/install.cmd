@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "PRODUCT=WebSQLMapper"
for %%I in ("%~dp0..") do set "SOURCE_ROOT=%%~fI"
if not defined WEBSQLMAPPER_INSTALL_ROOT set "WEBSQLMAPPER_INSTALL_ROOT=%LOCALAPPDATA%\WebSQLMapper"
set "INSTALL_ROOT=%WEBSQLMAPPER_INSTALL_ROOT%"
set "SRC_DIR=%INSTALL_ROOT%\src"
set "VENV_DIR=%INSTALL_ROOT%\venv"
set "BIN_DIR=%INSTALL_ROOT%\bin"
set "WRAPPER=%BIN_DIR%\websqlmapper.cmd"

echo [%PRODUCT%] Checking installed Python versions (minimum 3.10)...
call :find_python
if errorlevel 1 (
  echo [%PRODUCT%] Python 3.10+ not found. Attempting installation with winget...
  where winget >nul 2>&1 || goto :no_winget
  winget install --id Python.Python.3.13 --exact --silent --accept-package-agreements --accept-source-agreements
  if errorlevel 1 winget install --id Python.Python.3.10 --exact --silent --accept-package-agreements --accept-source-agreements
  call :find_python
  if errorlevel 1 goto :python_install_failed
)
where git >nul 2>&1
if errorlevel 1 (
  where winget >nul 2>&1
  if not errorlevel 1 (echo [%PRODUCT%] Installing Git for the update command...& winget install --id Git.Git --exact --silent --accept-package-agreements --accept-source-agreements >nul 2>&1) else echo [%PRODUCT%] WARNING: Git is unavailable; runtime works but update requires Git.
)
for /f "usebackq delims=" %%V in (`"%PY_EXE%" %PY_ARGS% -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"`) do set "SELECTED_MM=%%V"
echo [%PRODUCT%] Using existing compatible interpreter: %PY_DISPLAY% ^(Python %SELECTED_MM%^) 
if exist "%INSTALL_ROOT%\src.new" rmdir /s /q "%INSTALL_ROOT%\src.new"
if not exist "%INSTALL_ROOT%" mkdir "%INSTALL_ROOT%"
mkdir "%INSTALL_ROOT%\src.new" >nul 2>&1
robocopy "%SOURCE_ROOT%" "%INSTALL_ROOT%\src.new" /E /XD .venv .pytest_cache __pycache__ /XF *.pyc >nul
if errorlevel 8 goto :copy_failed
if exist "%SRC_DIR%" rmdir /s /q "%SRC_DIR%"
move "%INSTALL_ROOT%\src.new" "%SRC_DIR%" >nul || goto :copy_failed
if exist "%VENV_DIR%" rmdir /s /q "%VENV_DIR%"
"%PY_EXE%" %PY_ARGS% -m venv "%VENV_DIR%" || goto :venv_failed
for /f "usebackq delims=" %%V in (`"%VENV_DIR%\Scripts\python.exe" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"`) do set "VENV_MM=%%V"
if not "%SELECTED_MM%"=="%VENV_MM%" goto :version_mismatch
"%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel
if errorlevel 1 echo [%PRODUCT%] WARNING: packaging-tool upgrade failed; continuing.
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
"%WRAPPER%" --version >nul 2>&1 || goto :verify_failed
echo [%PRODUCT%] Installation verified with Python %VENV_MM%.
echo [%PRODUCT%] Command: websqlmapper
echo [%PRODUCT%] Home: %INSTALL_ROOT%
echo [%PRODUCT%] PATH entry: %BIN_DIR%
echo [%PRODUCT%] Open a new Command Prompt so the updated user PATH is loaded.
exit /b 0

:try_candidate
set "CANDIDATE_EXE=%~1"
set "CANDIDATE_ARGS=%~2"
set "CANDIDATE_DISPLAY=%~3"
"%CANDIDATE_EXE%" %CANDIDATE_ARGS% -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if errorlevel 1 exit /b 1
set "PY_EXE=%CANDIDATE_EXE%"
set "PY_ARGS=%CANDIDATE_ARGS%"
set "PY_DISPLAY=%CANDIDATE_DISPLAY%"
exit /b 0

:find_python
set "PY_EXE="
set "PY_ARGS="
set "PY_DISPLAY="
where python >nul 2>&1
if not errorlevel 1 (
  call :try_candidate "python" "" "python"
  if not errorlevel 1 exit /b 0
)
where python3 >nul 2>&1
if not errorlevel 1 (
  call :try_candidate "python3" "" "python3"
  if not errorlevel 1 exit /b 0
)
where py >nul 2>&1
if not errorlevel 1 (
  call :try_candidate "py" "-3" "py -3"
  if not errorlevel 1 exit /b 0
  for %%V in (3.14 3.13 3.12 3.11 3.10) do (
    call :try_candidate "py" "-%%V" "py -%%V"
    if not errorlevel 1 exit /b 0
  )
)
for %%D in (Python314 Python313 Python312 Python311 Python310) do (
  if exist "%LOCALAPPDATA%\Programs\Python\%%D\python.exe" (
    call :try_candidate "%LOCALAPPDATA%\Programs\Python\%%D\python.exe" "" "%LOCALAPPDATA%\Programs\Python\%%D\python.exe"
    if not errorlevel 1 exit /b 0
  )
)
exit /b 1

:set_environment
setx WEBSQLMAPPER_HOME "%INSTALL_ROOT%" >nul
set "USER_PATH="
for /f "tokens=2,*" %%A in ('reg query HKCU\Environment /v Path 2^>nul ^| findstr /I "Path"') do set "USER_PATH=%%B"
if not defined USER_PATH (reg add HKCU\Environment /v Path /t REG_EXPAND_SZ /d "%BIN_DIR%" /f >nul& exit /b 0)
echo ;%USER_PATH%; | findstr /I /C:";%BIN_DIR%;" >nul
if errorlevel 1 reg add HKCU\Environment /v Path /t REG_EXPAND_SZ /d "%USER_PATH%;%BIN_DIR%" /f >nul
exit /b 0

:no_winget
echo [%PRODUCT%] ERROR: Python 3.10+ is missing and winget is unavailable. Install Python 3.10 or newer, then rerun this installer. 1>&2
exit /b 1
:python_install_failed
echo [%PRODUCT%] ERROR: Python installation failed or no Python 3.10+ interpreter was discoverable. 1>&2
exit /b 1
:copy_failed
echo [%PRODUCT%] ERROR: Failed to copy project files into %SRC_DIR%. 1>&2
exit /b 1
:venv_failed
echo [%PRODUCT%] ERROR: Failed to create the isolated Python environment. 1>&2
exit /b 1
:version_mismatch
echo [%PRODUCT%] ERROR: Virtual environment Python %VENV_MM% does not match selected Python %SELECTED_MM%. 1>&2
exit /b 1
:pip_failed
echo [%PRODUCT%] ERROR: Failed to install Python dependencies/package for Python %SELECTED_MM%. 1>&2
exit /b 1
:verify_failed
echo [%PRODUCT%] ERROR: Installation completed but the websqlmapper command verification failed. 1>&2
exit /b 1
