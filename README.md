# parsiya.net ![Deploy Blog](https://github.com/parsiya/parsiya.net/workflows/Deploy%20Blog/badge.svg)
This is the source for my personal website at https://parsiya.net.

It is generated using [Hugo][hugo] and the [Hugo-Octopress Theme][hugo-octopress].
I ported the [Octopress][octopress] classic theme to Hugo.

[hugo]: https://gohugo.io/
[hugo-octopress]: https://github./parsiya/hugo-octopress
[octopress]: https://github.com/octopress/octopress

## Workflow

1. Create a new post with `hugo new post/2018-11-23-post-name/index.markdown`
   (or `index.md`).
2. Edit the post and proofread. Pictures are in the same
   directory to take advantage of [page bundles][page-bundles].
  1. `ctrl+shift+b` in VS Code starts a task that runs the Hugo watch server and
     opens it in a browser. See [.vscode/tasks.json](.vscode/tasks.json).
3. Push to Github.
4. Github action takes over and builds the site.
    * See the "Deploying" section below for more information.
5. [s3deploy][s3deploy] uploads the results to AWS.
6. ???
7. Profit. The website is now updated. Add CI/CD to your resume.

[page-bundles]: https://gohugo.io/content-management/page-bundles/
[s3deploy]: https://github.com/bep/s3deploy

## Hosting
The website is hosted in an AWS S3 bucket. CloudFront provides CDN and TLS (and
certificate). GitHub pages are also popular (and free). See my blog post
[Automagically Deploying Websites with Custom Domains to Github Pages][gh-pages].

[gh-pages]: https://parsiya.net/blog/2021-02-17-automagically-deploying-websites-with-custom-domains-to-github-pages/

## Deploying
I use a custom GitHub action. See [deploy.yml](.github/workflows/deploy.yml).

### s3deploy
I use [s3deploy][s3deploy] to deploy the blog to AWS. The configuration is
inside [.s3deploy.yml](.s3deploy.yml). [This example][s3deploy-config] is
suitable (with a bit of modification) for most static websites.

[s3deploy-config]: https://github.com/bep/s3deploy#advanced-configuration

Static resources (fonts, images, css, etc.) do not have expiration dates.
Everything else uses gzip compression. When a resource is updated, s3deploy
invalidates its CloudFront cache.

**Note**: Enabling `gzip compression` for Keybase proofs (see
[static/keybase.txt](static/keybase.txt)) breaks them.

Use the s3deploy's [example IAM policy][s3deploy-iam]. At the time of writing,
AWS does not support addressing separate CloudFront distributions with ARNs
(Amazon Resource Names) so the resulting key can list and invalidate all
distributions.

[s3deploy-iam]: https://github.com/bep/s3deploy#cloudfront-cdn-cache-invalidation

### Travis CI - Not Used Anymore
The blog used to use Travis CI. See [@archive/.travis.yml](@archive/.travis.yml).

* The theme is a submodule. It's updated first.
* Install two debs. Hugo and s3deploy. I like to control the versions as both
  software are under heavy development.
* `language:minimal` reduces build time by 20 seconds (compared to the default
  container).
* AWS key and secret are in `AWS_ACCESS_KEY` and `AWS_SECRET_ACCESS_KEY`
  environment variables respectively. These are used by s3deploy.

See [@archive/deploy.bat](@archive/deploy.bat) for manual deployment.
