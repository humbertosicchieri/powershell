@ECHO off
rem Logs off all disconnected users
SETLOCAL
SET "servers=hostname server"
FOR %%s IN (%servers%) DO (
	FOR /f "tokens=2" %%a IN ('"Quser /server:%%s | findstr Disc"') DO (
		rwinsta /server:%%s %%a
	)
)
