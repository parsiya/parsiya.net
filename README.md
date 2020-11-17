# parsiya.net ![Deploy Status](https://github.com/parsiya/parsiya.net/workflows/.github/workflows/deploy.yml/badge.svg)
This is the source for my personal website at https://parsiya.net.

It is generated using [Hugo](https://gohugo.io/) and the [Hugo-Octopress Theme](https://github./parsiya/hugo-octopress). I ported the [Octopress](https://github.com/octopress/octopress) classic theme.

## Workflow

1. Create a new post with `hugo new post/2018-11-23-post-name/index.markdown` (or `index.md`).
2. Edit the post and proofread with `hugo serve -vw`. Pictures are in the same directory to take advantage of [page bundles](https://gohugo.io/content-management/page-bundles/).
3. Push to Github.
4. Github action takes over and publishes the blog using .
    * See the "Deploying" section below for more information.
5. Uploading the files to AWS is done with [s3deploy](https://github.com/bep/s3deploy)
6. ???
7. Profit. The website is now updated. Add CI/CD to your resume.

## Hosting
The website is hosted in an AWS S3 bucket. CloudFront provides CDN and TLS (and certificate).

## Deploying
I use a custom github action. See [deploy.yml](..github/workflows/deploy.yml).

### s3deploy
I use [s3deploy](https://github.com/bep/s3deploy) to deploy the blog to AWS. The configuration is inside [.s3deploy.yml](.s3deploy.yml). [This example](https://github.com/bep/s3deploy#advanced-configuration) is suitable (with a bit of modification) for most static websites.

Static resources (fonts, images, css, etc.) do not have expiration dates. Everything else uses gzip compression. When a resource is updated, s3deploy invalidates its CloudFront cache.

Note: Enabling `gzip compression` for Keybase proofs (see [static/keybase.txt](static/keybase.txt)) breaks it.

Use the s3deploy's [example IAM policy](https://github.com/bep/s3deploy#cloudfront-cdn-cache-invalidation). AWS does not support addressing separate CloudFront distributions with ARNs (Amazon Resource Names) so the resulting key can list and invalidate all distributions.

### Travis CI - Not Used Anymore
The blog used to use Travis CI. See [.travis.OLDyml](.travis.OLDyml).

* The theme is a submodule. It's updated first.
* Install two debs. Hugo and s3deploy. I like to control the versions as both software are under heavy development.
* `language:minimal` reduces build time by 20 seconds (compared to the default container).
* AWS key and secret are in `AWS_ACCESS_KEY` and `AWS_SECRET_ACCESS_KEY` environment variables respectively. These are used by s3deploy.

See [deploy.bat](deploy.bat) for manual deployment.
