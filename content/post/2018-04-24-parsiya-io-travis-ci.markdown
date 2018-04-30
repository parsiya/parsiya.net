---
title: "Deploying my Knowledge Base at parsiya.io to S3 with Travis CI"
date: 2018-04-24T01:02:03-04:00
draft: false
toc: false
comments: true
categories:
- Not Security
- Clone
tags:
- Blog
- Travis CI
- Hugo
---

I finally managed to automate deployment of [parsiya.io](http://parsiya.io) with Travis CI. Not having dones this before, I encountered some pitfalls. Additionally I had two extra problems:

- The structure of the blog is different from most Hugo deployments. [Parsia-Clone][parsia-clone-github] only contains the `content` directory. Parents and everything else are in the [parsiya.io][parsiya-io-github] repo. So while we push to `Parsia-Clone`, we need to clone `parsiya.io` and build the repository there.
- I am hosting it out of an S3 bucket. All other examples were using github pages.

[parsia-clone-github]: https://github.com/parsiya/Parsia-Clone
[parsiya-io-github]: https://github.com/parsiya/Parsiya.io

<!--more-->

# TL;DR

1. Sign into [travis-ci.org][travis-ci-org] with your Github account.
2. Alternatively create an access token. All my repositories are public so I do not care.
3. Add the repository containing the content. In this case `Parsia-Clone`.
    * Enable `Build pushed branches`.
4. Create the destination S3 bucket (e.g. `BUCKET_NAME`).
5. Create the following Amazon IAM policy and substitute `BUCKET_NAME`. This policy only gives read/write access to `BUCKET_NAME`.
{{< codecaption title="travis-write-policy" lang="json" >}}
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::BUCKET_NAME"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload",
        "s3:GetObjectAcl",
        "s3:PutObjectAcl"
      ],
      "Resource": [
        "arn:aws:s3:::BUCKET_NAME/*"
      ]
    }
  ]
}
{{< /codecaption >}}
6. Create a group with the previous policy (e.g. `travis-writers`).
7. Create a user and add it to the `travis-writers` group. Copy the AWS access/secret keys.
8. Create `.travis.yml` in `Parsia-Clone`.
{{< codecaption title=".travis.yml" lang="yaml" >}}
# safelist - only build on pushes to these branches
branches:
  only:
  - master
  - travis
# we needed this if wanted to build Hugo manually
# language: go
# go:
# - 1.10
install:
# change this version as it goes up
# get and install Hugo
- wget https://github.com/gohugoio/hugo/releases/download/v0.40/hugo_0.40_Linux-64bit.deb
- sudo dpkg -i hugo*.deb
# clone the parent repository, note this is different from Parsia-Clone
- git clone https://github.com/parsiya/parsiya.io
- cd parsiya.io
# update and fetch submodules
- git submodule init
- git submodule update --recursive --remote
script:
# build the website with Hugo, output will be in public directory
- hugo
# deploy public directory to the bucket
deploy:
  provider: s3
  access_key_id: $AWS_ACCESS_KEY
  secret_access_key: $AWS_SECRET_KEY
  bucket: BUCKET_NAME
  region: us-east-1
  local-dir: public
  skip_cleanup: true
  acl: public_read
  on:
    # make it work on branch other than master
    # change this to master or any other branch if needed
    branch: travis
{{< /codecaption >}}
9. Add the AWS keys in `Settings > Environment Variables` (do not include `$`):
    - `AWS_ACCESS_KEY`
    - `AWS_SECRET_KEY`
10. Push any object and enjoy the deployed blog in your bucket.

Now for the longer version.

# Setup
My git structure is unnecessarily complex. I will explain it in detail in a different blog post. But I wanted to keep `Parsia-Clone` intact and did not want to add the modified [Hugo-Octopress][hugo-octopress-github] them to it. `Parsia-Clone` is in the `content` directory. The parent them is in the [parsiya.io][parsiya-io-github] repository that contains the theme and the clone as submodules.

After every push to the `Parsia-Clone` repository. Travis CI will:

1. Create a new default container with Go.
2. Install Hugo.
3. Clone the `parsiya.io` directory.
4. Update and fetch submodules (theme and `Parsia-Clone`).
5. Build the website and deploy it to S3.
6. ???
7. Profit.

We can see it in the `travis.yml` file above. Let's talk about them a bit:

## safelist
Safelist tells Travis CI to only build on certain branches. In this case, I am pushing to `master` and `travis`.

``` yaml
# safelist - only build on pushes to these branches
branches:
  only:
  - master
  - travis
```

## language
If you want to build Hugo manually instead of downloading a deb, you can install Go and configure it.

``` yaml
language: go
go:
- 1.10
```

## install
`install` runs commands after push and is setting up the environment:

1. `wget https://github.com/gohugoio/hugo/releases/download/v0.40/hugo_0.40_Linux-64bit.deb`
    * Download the Hugo `deb`. At the time of writing, version `0.40` is out. 
2. `sudo dpkg -i hugo*.deb`
    * Install the `deb` file.
3. `git clone https://github.com/parsiya/parsiya.io`
    * Clone the parent repository.
4. `git submodule init` - `git submodule update --recursive --remote`
    * Update and fetch submodules. The submodules might have been updated since the last commit to `parsiya.io`, so they must be updated.

``` yaml
install:
# change this version as it goes up
# get and install Hugo
- wget https://github.com/gohugoio/hugo/releases/download/v0.40/hugo_0.40_Linux-64bit.deb
- sudo dpkg -i hugo*.deb
# clone the parent repository, note this is different from Parsia-Clone
- git clone https://github.com/parsiya/parsiya.io
- cd parsiya.io
# update and fetch submodules
- git submodule init
- git submodule update --recursive --remote
```

## script
Now we will build the blog by running `hugo`. This command without any parameters will build the current website and put it in the `public` directory.

## deploy

* Deploy to S3 every time the `travis` branch is updated. `on` at the bottom of the file.
* Access and secret keys are set in environmental variables above.
* Region is `us-east-1`. This is the default region and does not need to be provided, if you bucket is in a different region be sure to change this.
* `local-dir: public`: Copy the `public` directory to the bucket.
* `bucket: BUCKET_NAME`: Destination bucket, change this.
* `skip_cleanup: true`: Do not delete the build artifacts.
* `acl: public_read`: Grant everyone read access to the bucket objects. This is only needed if you want to deploy the bucket via HTTP. If you want to deploy it over TLS via CloudFront, remove this and configure your bucket permissions for CloudFront properly.

## Pitfalls
Being the first time that I have used Travis CI, I encountered some errors. I am documenting them here because inevitably me and some other people get these errors. You're welcome future me.

### Add Environmental Variables with $ in Travis CI Web UI
Initially when adding the environmental variables, I had added them as they appear in `travis.yml` file. Meaning they started with `$`. I am not sure why I had added them with the prefix. The error will be similar to:

- `The previous command failed, possibly due to a malformed secure environment variable.`

**Solution:** Don't add your environmental variables with `$`.

### Error with go get Hugo
To build Hugo from source, I initially had setup the container to have `Go` and then use `go get` to download and build Hugo. I got this error `imports context: unrecognized import path "context"`.

``` go
$ go get github.com/gohugoio/hugo
package github.com/gohugoio/hugo
    imports context: unrecognized import path "context"
The command "go get github.com/gohugoio/hugo" failed and exited with 1 during .
```

**Solution:** I decided to not build Hugo from source and just download and instead install the lastest `deb` release.

### Repository Name not Matching the Condition in Deploy
I am building inside the `parsiya.io` repo but I had originally added `Parsia-Clone` as condition in deployment in `travis.yml` like this:

``` yaml
deploy:
  provider: s3
  # ... 
  acl: public_read
  on:
    # Make it work on branch other than master.
    branch: travis
    repo: parsiya/parsia-clone
```

I got this error:

- `this repo's name does not match one specified in .travis.yml's deploy.on.repo`.

**Solution**: Remove the `repo` condition. It's not needed.

### No DeleteObject Permission in AWS User Policy
If you do not give permission to delete the previous versions in the bucket (overwriting), the build will fail. The error message is a bit vague:

- `Oops, It looks like you tried to write to a bucket that isn't yours or doesn't exist yet. Please create the bucket before trying to write to it.`

This error message in general means you do not have enough access. I had initially only given `PutObject` and `GetObject`.

**Solution:** Add the following permissions:

- `s3:PutObject`
- `s3:GetObject`
- `s3:DeleteObject`
- `s3:AbortMultipartUpload`
- `s3:GetObjectAcl`
- `s3:PutObjectAcl`

<!-- Links -->

[travis-ci-org]: https://travis-ci.org/
[hugo-octopress-github]: https://github.com/parsiya/Hugo-Octopress
