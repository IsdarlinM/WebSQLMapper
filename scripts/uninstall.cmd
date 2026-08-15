@echo off
setlocal EnableExtensions DisableDelayedExpansion
if not defined WEBSQLMAPPER_INSTALL_ROOT set "WEBSQLMAPPER_INSTALL_ROOT=%LOCALAPPDATA%\WebSQLMapper"
set "INSTALL_ROOT=%WEBSQLMAPPER_INSTALL_ROOT%"
set "BIN_DIR=%INSTALL_ROOT%\bin"
if exist "%INSTALL_ROOT%" rmdir /s /q "%INSTALL_ROOT%"
reg delete HKCU\Environment /v WEBSQLMAPPER_HOME /f >nul 2>&1
set "USER_PATH="
for /f "tokens=2,*" %%A in ('reg query HKCU\Environment /v Path 2^>nul ^| findstr /I "Path"') do set "USER_PATH=%%B"
if defined USER_PATH (
  set "NEW_PATH=%USER_PATH%"
  call set "NEW_PATH=%%NEW_PATH:%BIN_DIR%;=%%"
  call set "NEW_PATH=%%NEW_PATH:;%BIN_DIR%=%%"
  reg add HKCU\Environment /v Path /t REG_EXPAND_SZ /d "%NEW_PATH%" /f >nul
)
echo [WebSQLMapper] Runtime removed. User templates/config under %%APPDATA%%\WebSQLMapper are preserved.
exit /b 0
