REM Using s3deploy
rd /q /s public
hugo
rd /q /s public\post
del /s /a .\*thumbs*.db
REM del /s /a public\categories\*index*.xml
REM del /s /a public\tags\*index*.xml
REM Distribution ID is not supposed to be secret, so here we go commit it to github.
s3deploy.exe -source=public/ -region=us-east-1 -bucket=parsiya.net -distribution-id E3S0DM3VADRBW7
rd /q /s public
