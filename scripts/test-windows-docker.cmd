@echo off
setlocal EnableExtensions
where docker >nul 2>&1
if errorlevel 1 (
  echo [WebSQLMapper] ERROR: Docker is not installed or not on PATH. 1>&2
  exit /b 1
)

docker info --format "{{.OSType}}" 2>nul | findstr /I /X "windows" >nul
if errorlevel 1 (
  echo [WebSQLMapper] ERROR: Docker is not running in Windows-container mode. 1>&2
  exit /b 1
)

docker build -f docker\Dockerfile.windows -t websqlmapper-windows-installer .
if errorlevel 1 exit /b 1
docker run --rm websqlmapper-windows-installer
exit /b %errorlevel%
