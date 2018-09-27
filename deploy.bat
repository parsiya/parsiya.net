REM Using s3deploy
rd /q /s public
hugo
rd /q /s public\post
del /s /a .\*thumbs*.db
REM del /s /a public\categories\*index*.xml
REM del /s /a public\tags\*index*.xml
s3deploy.exe -source=public/ -region=us-east-1 -bucket=parsiya.net
rd /q /s public
