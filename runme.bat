del public
hugo
python s3cmd sync --acl-public --delete-removed -MP --rr public/ s3://parsiya.net
python s3cmd --acl-public --no-preserve --mime-type="text/css" put public/css/hugo-octopress.css s3://parsiya.net/css/hugo-octopress.css
del public
