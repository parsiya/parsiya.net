rd /q /s public
hugo
rd /q /s public\post
del /s /a .\*thumbs*.db
del /s /a public\categories\*index*.xml
del /s /a public\tags\*index*.xml
python s3cmd sync --acl-public --delete-removed -MP --cf-invalidate --rr public/ s3://parsiya.net
python s3cmd --acl-public --no-preserve --cf-invalidate --mime-type="text/css" put public/css/hugo-octopress.css s3://parsiya.net/css/hugo-octopress.css
rd /q /s public
