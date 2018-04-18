@echo off

@if not "%ECHO%" == ""  echo %ECHO%
@if "%OS%" == "Windows_NT" setlocal
rem Set to all parameters by default
set SERVER_OPTS=%*

if "%OS%" == "Windows_NT" (
  set "DIRNAME=%~dp0%"
) else (
  set DIRNAME=.\
)

setlocal EnableDelayedExpansion
rem check for the security manager system property
echo(!SERVER_OPTS! | findstr /r /c:"-Djava.security.manager" > nul
if not errorlevel == 1 (
    echo ERROR: The use of -Djava.security.manager has been removed. Please use the -secmgr command line argument or SECMGR=true environment variable.
    GOTO :EOF
)
setlocal DisableDelayedExpansion

rem Read command-line args.
:READ-ARGS
if "%~1" == "" (
   goto MAIN
) else if "%~1" == "-secmgr" (
   set SECMGR=true
)
shift
goto READ-ARGS

:MAIN

rem check for secmgr property
setlocal EnableDelayedExpansion
echo(!JAVA_OPTS! | findstr /r /c:"-Dsecmgr" > nul
if not errorlevel == 1 (
   set "line=%JAVA_OPTS%"
   set JAVA_OPTS=!line:-Dsecmgr= !
   set SECMGR=true
)
setlocal DisableDelayedExpansion

pushd "%DIRNAME%.."
set "RESOLVED_JBOSS_HOME=%CD%"
popd

if "x%JBOSS_HOME%" == "x" (
  set "JBOSS_HOME=%RESOLVED_JBOSS_HOME%"
)

pushd "%JBOSS_HOME%"
set "SANITIZED_JBOSS_HOME=%CD%"
popd

if /i "%RESOLVED_JBOSS_HOME%" NEQ "%SANITIZED_JBOSS_HOME%" (
   echo.
   echo   WARNING:  JBOSS_HOME may be pointing to a different installation - unpredictable results may occur.
   echo.
   echo       JBOSS_HOME: "%JBOSS_HOME%"
   echo.
)

rem Setup JBoss specific properties
if "x%JAVA_HOME%" == "x" (
  set  JAVA=java
  echo JAVA_HOME is not set. Unexpected results may occur.
  echo Set JAVA_HOME to the directory of your local JDK to avoid this message.
) else (
  if not exist "%JAVA_HOME%" (
    echo JAVA_HOME "%JAVA_HOME%" path doesn't exist
    goto END
   ) else (
     if not exist "%JAVA_HOME%\bin\java.exe" (
       echo "%JAVA_HOME%\bin\java.exe" does not exist
       goto END_NO_PAUSE
     )
      echo Setting JAVA property to "%JAVA_HOME%\bin\java"
    set "JAVA=%JAVA_HOME%\bin\java"
  )
)

rem Find jboss-modules.jar, or we can't continue
if exist "%JBOSS_HOME%\jboss-modules.jar" (
    set "JBOSS_RUNJAR=%JBOSS_HOME%\jboss-modules.jar"
) else (
  echo Could not locate "%JBOSS_HOME%\jboss-modules.jar".
  echo Please check that you are in the bin directory when running this script.
  goto END
)


rem Set the module options
set "MODULE_OPTS="
if "%SECMGR%" == "true" (
    set "MODULE_OPTS=-secmgr"
)


rem Set default module root paths
if "x%JBOSS_MODULEPATH%" == "x" (
  set "JBOSS_MODULEPATH=%JBOSS_HOME%\modules"
)

set "JAVA_OPTS=%JAVA_OPTS% -Dprogram.name=wsprovide.bat"

"%JAVA%" %JAVA_OPTS% ^
    -jar "%JBOSS_RUNJAR%" ^
    %MODULE_OPTS% ^
    -mp "%JBOSS_MODULEPATH%" ^
    org.jboss.ws.tools.wsprovide ^
    %*

:END
