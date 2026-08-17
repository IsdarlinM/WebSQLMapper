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

call :find_python
if errorlevel 1 (
  echo [%PRODUCT%] Python 3.10+ not found. Attempting installation with winget...
  where winget >nul 2>&1
  if errorlevel 1 goto :no_winget
  winget install --id Python.Python.3.13 --exact --silent --accept-package-agreements --accept-source-agreements
  if errorlevel 1 winget install --id Python.Python.3.10 --exact --silent --accept-package-agreements --accept-source-agreements
  call :find_python
  if errorlevel 1 goto :python_install_failed
)

call :capture_selected_version
if errorlevel 1 goto :python_probe_failed

echo [%PRODUCT%] Using existing compatible interpreter: %PY_DISPLAY% ^(Python %SELECTED_MM%^)

where git >nul 2>&1
if errorlevel 1 (
  where winget >nul 2>&1
  if not errorlevel 1 (
    echo [%PRODUCT%] Installing Git for the update command...
    winget install --id Git.Git --exact --silent --accept-package-agreements --accept-source-agreements >nul 2>&1
  ) else (
    echo [%PRODUCT%] WARNING: Git is unavailable; runtime works but update requires Git.
  )
)

if exist "%INSTALL_ROOT%\src.new" rmdir /s /q "%INSTALL_ROOT%\src.new"
if not exist "%INSTALL_ROOT%" mkdir "%INSTALL_ROOT%"
mkdir "%INSTALL_ROOT%\src.new" >nul 2>&1
robocopy "%SOURCE_ROOT%" "%INSTALL_ROOT%\src.new" /E /XD .git .venv .pytest_cache __pycache__ /XF *.pyc >nul
if errorlevel 8 goto :copy_failed
if exist "%SRC_DIR%" rmdir /s /q "%SRC_DIR%"
move "%INSTALL_ROOT%\src.new" "%SRC_DIR%" >nul
if errorlevel 1 goto :copy_failed

if exist "%VENV_DIR%" rmdir /s /q "%VENV_DIR%"
"%PY_EXE%" %PY_ARGS% -m venv "%VENV_DIR%"
if errorlevel 1 goto :venv_failed

call :capture_venv_version
if errorlevel 1 goto :venv_probe_failed
if /I not "%SELECTED_MM%"=="%VENV_MM%" goto :version_mismatch

echo [%PRODUCT%] Installing dependencies into Python %VENV_MM%...
"%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip setuptools wheel
if errorlevel 1 echo [%PRODUCT%] WARNING: packaging-tool upgrade failed; continuing with the versions already available.

"%VENV_DIR%\Scripts\python.exe" -m pip install -e "%SRC_DIR%[socks]"
if errorlevel 1 (
  echo [%PRODUCT%] WARNING: optional SOCKS support failed; installing core dependencies only.
  "%VENV_DIR%\Scripts\python.exe" -m pip install -e "%SRC_DIR%"
  if errorlevel 1 goto :pip_failed
)

if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
>"%WRAPPER%" echo @echo off
>>"%WRAPPER%" echo "%VENV_DIR%\Scripts\python.exe" -m websqlmapper %%*

rem Make the command available immediately inside this Command Prompt.
set "PATH=%BIN_DIR%;%PATH%"
set "WEBSQLMAPPER_HOME=%INSTALL_ROOT%"

if not "%WEBSQLMAPPER_SKIP_PATH%"=="1" (
  "%VENV_DIR%\Scripts\python.exe" "%SRC_DIR%\scripts\windows_env.py" --home "%INSTALL_ROOT%" --bin "%BIN_DIR%"
  if errorlevel 1 goto :environment_failed
)

rem CALL is required because WRAPPER is itself a .cmd file.
call "%WRAPPER%" --version >nul 2>&1
if errorlevel 1 goto :verify_failed
where websqlmapper >nul 2>&1
if errorlevel 1 goto :path_verify_failed
call websqlmapper --version >nul 2>&1
if errorlevel 1 goto :path_verify_failed

echo [%PRODUCT%] Installation verified with Python %VENV_MM%.
echo [%PRODUCT%] Command: websqlmapper
echo [%PRODUCT%] Home: %INSTALL_ROOT%
echo [%PRODUCT%] PATH entry: %BIN_DIR%
if "%WEBSQLMAPPER_SKIP_PATH%"=="1" (
  echo [%PRODUCT%] PATH persistence was skipped by WEBSQLMAPPER_SKIP_PATH=1.
) else (
  echo [%PRODUCT%] User environment variables were updated successfully.
  echo [%PRODUCT%] This Command Prompt can use websqlmapper immediately.
  echo [%PRODUCT%] PowerShell or other already-open terminals may need to be reopened.
)

set "FINAL_HOME=%WEBSQLMAPPER_HOME%"
set "FINAL_PATH=%PATH%"
endlocal & set "WEBSQLMAPPER_HOME=%FINAL_HOME%" & set "PATH=%FINAL_PATH%"
exit /b 0

:find_python
set "PY_EXE="
set "PY_ARGS="
set "PY_DISPLAY="
echo [%PRODUCT%] Checking installed Python versions ^(minimum 3.10^)...

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
if exist "%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" (
  call :try_candidate "%LOCALAPPDATA%\Programs\Python\Launcher\py.exe" "-3" "Python Launcher"
  if not errorlevel 1 exit /b 0
)
for %%D in (Python314 Python313 Python312 Python311 Python310) do (
  if exist "%LOCALAPPDATA%\Programs\Python\%%D\python.exe" (
    call :try_candidate "%LOCALAPPDATA%\Programs\Python\%%D\python.exe" "" "%LOCALAPPDATA%\Programs\Python\%%D\python.exe"
    if not errorlevel 1 exit /b 0
  )
  if exist "%ProgramFiles%\%%D\python.exe" (
    call :try_candidate "%ProgramFiles%\%%D\python.exe" "" "%ProgramFiles%\%%D\python.exe"
    if not errorlevel 1 exit /b 0
  )
)
exit /b 1

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

:capture_selected_version
set "VERSION_FILE=%TEMP%\websqlmapper-python-version-%RANDOM%-%RANDOM%.tmp"
del /q "%VERSION_FILE%" >nul 2>&1
"%PY_EXE%" %PY_ARGS% -c "import sys; print(str(sys.version_info.major)+'.'+str(sys.version_info.minor))" >"%VERSION_FILE%" 2>nul
if errorlevel 1 (
  del /q "%VERSION_FILE%" >nul 2>&1
  exit /b 1
)
set "SELECTED_MM="
set /p "SELECTED_MM=" <"%VERSION_FILE%"
del /q "%VERSION_FILE%" >nul 2>&1
if not defined SELECTED_MM exit /b 1
exit /b 0

:capture_venv_version
set "VERSION_FILE=%TEMP%\websqlmapper-venv-version-%RANDOM%-%RANDOM%.tmp"
del /q "%VERSION_FILE%" >nul 2>&1
"%VENV_DIR%\Scripts\python.exe" -c "import sys; print(str(sys.version_info.major)+'.'+str(sys.version_info.minor))" >"%VERSION_FILE%" 2>nul
if errorlevel 1 (
  del /q "%VERSION_FILE%" >nul 2>&1
  exit /b 1
)
set "VENV_MM="
set /p "VENV_MM=" <"%VERSION_FILE%"
del /q "%VERSION_FILE%" >nul 2>&1
if not defined VENV_MM exit /b 1
exit /b 0

:no_winget
echo [%PRODUCT%] ERROR: Python 3.10+ is missing and winget is unavailable. Install Python 3.10 or newer, then rerun this installer. 1>&2
exit /b 1
:python_install_failed
echo [%PRODUCT%] ERROR: Python installation failed or no Python 3.10+ interpreter was discoverable. 1>&2
exit /b 1
:python_probe_failed
echo [%PRODUCT%] ERROR: The selected Python interpreter could not report its version. 1>&2
exit /b 1
:copy_failed
echo [%PRODUCT%] ERROR: Failed to copy project files into %SRC_DIR%. 1>&2
exit /b 1
:venv_failed
echo [%PRODUCT%] ERROR: Failed to create the isolated Python environment. 1>&2
exit /b 1
:venv_probe_failed
echo [%PRODUCT%] ERROR: The virtual environment Python interpreter could not report its version. 1>&2
exit /b 1
:version_mismatch
echo [%PRODUCT%] ERROR: Virtual environment Python %VENV_MM% does not match selected Python %SELECTED_MM%. 1>&2
exit /b 1
:pip_failed
echo [%PRODUCT%] ERROR: Failed to install Python dependencies/package for Python %SELECTED_MM%. 1>&2
exit /b 1
:environment_failed
echo [%PRODUCT%] ERROR: Failed to persist WEBSQLMAPPER_HOME or the user PATH. 1>&2
exit /b 1
:verify_failed
echo [%PRODUCT%] ERROR: Installation completed but the direct wrapper verification failed. 1>&2
exit /b 1
:path_verify_failed
echo [%PRODUCT%] ERROR: The websqlmapper command is not resolvable through PATH in this Command Prompt. 1>&2
exit /b 1
