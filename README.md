# parsiya.net [![Build Status](https://travis-ci.org/parsiya/parsiya.net.svg?branch=master)](https://travis-ci.org/parsiya/parsiya.net)
This is the source for my personal website at https://parsiya.net.

It is generated using [Hugo](https://gohugo.io/) and the [Hugo-Octopress Theme](https://github./parsiya/hugo-octopress) (made by yours truly). Looking at the theme, you can see it's a port of [Octopress](https://github.com/octopress/octopress).

## Hosting
The website is hosted in an S3 bucket with CloudFront in front of it to leverage the CDN and provide TLS.

When updating the contents of the bucket, be sure to invalidate the CloudFront cache. This can be done either in the console or tools. AWS charges by "invalidation URL" (free 1000/month URLs) so when in doubt just do a complete purge with `/*` (which counts as one URL).

## Deployment
Currently I use [s3deploy](https://github.com/bep/s3deploy). It reads its configuration from the [.s3deploy.yml](.s3deploy.yml) file. [The example](https://github.com/bep/s3deploy#advanced-configuration) is suitable (with a bit of modification) for most static websites.

Note: If you enable `gzip compression` for keybase proofs, your proof will break.

Manual update is via [deploy.bat](deploy.bat) or CI integration with [.travis.yml](.travis.yml). Both roughly do the same thing, build the website and then push it to the bucket with s3deploy.

Use the s3deploy's [example IAM policy](https://github.com/bep/s3deploy#cloudfront-cdn-cache-invalidation). AWS does not support addressing separate CloudFront distributions with ARNs (Amazon Resource Names) so the user can list and invalidate all distributions. I have published the CloudFront distribution ID to this repository. I could not find any information saying it should be secret.

Previously I used [s3cmd](https://github.com/s3tools/s3cmd). You can see the batch file in [runme.batold](runme.batold).