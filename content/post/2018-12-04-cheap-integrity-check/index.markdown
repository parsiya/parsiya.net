---
title: "Cheap Integrity Checks with HEAD"
date: 2018-12-04T22:51:03-05:00
draft: false
toc: false
comments: true
twitterImage: 04-head.png
categories:
- npm
- Burp
---

**tl;dr:** HEAD returns file size in `Content-Length` response header.

A few months ago, I did a side project of creating a Go package for npm. It was before the current dumpster fire that is [event-stream](https://github.com/dominictarr/event-stream/issues/116). The idea was to be able to query npm and get information and packages.

<!--more-->

# The Problem
As part of the metadata check, I wanted to see if a package's tarball size matches the size mentioned in the metadata. Downloading the file and checking the size works but is slow because the file has to be downloaded.

# The Solution
Running `HEAD` on a tarball, does not return the file but the response will have the `Content-Length` header. The header will have the size of the file.

In [RFC 2616 - Hypertext Transfer Protocol -- HTTP/1.1 - Section 14.13 Content-Length](https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.13) we can read:

> The Content-Length entity-header field indicates [...] in the case of the HEAD method, the size of the entity-body that would have been sent had the request been a GET.

## npm Registry Documentation
The npm APIs were a bit hard to find. Here's a link and you're welcome:

* https://github.com/npm/registry

Everyone seems to be using the app. 17K Github stars for the app and only 19 for the documentation. Github stars are how people rank themselves in the JS ecosystem right?

Hint: Hit me up if you want to do some supply chain attacks on the app itself.

## Package Metadata
[Full package metadata](https://github.com/npm/registry/blob/master/docs/responses/package-metadata.md#package-metadata) can be access by sending a GET request to `https://{{registry_url}}/{{package_name}}` (if the package name is not unique, it will do a search but let's not worry about that). E.g. https://registry.npmjs.org/lodash. [Lodash](https://www.npmjs.com/package/lodash) is the most depended upon package according to https://www.npmjs.com/browse/depended.

{{< imgcap title="Lodash metadata" src="01-lodash-metadata.png" >}}

{{< imgcap title="Lodash full metadata in Burp" src="02-lodash-burp.png" >}}

Retrieve short package metadata by sending a GET request to the same URL but with the following header:

* `Accept: application/vnd.npm.install-v1+json`

{{< imgcap title="Lodash short metadata in Burp" src="03-lodash-short.png" >}}

You can see the tarball address in the screenshot.

* http://registry.npmjs.org/lodash/-/lodash-0.1.0.tgz

Note: While the addresses are `http`, npm registry will redirect them to `https`.

Now we can run `HEAD` to get the size.

{{< imgcap title="Also look at that fancy npm-notice header" src="04-head.png" >}}

## The Bug
This has a ~~feature~~ bug. The header returns the size of the response. If the file is not there or the response contains an error, then the header value will not be accurate and I hit some false positives. For example, Vue.js 0.8.6.

{{< imgcap title="Vue.js 0.8.6 in short metadata" src="05-vue-metadata.png" >}}

According to the metadata it should be there at http://registry.npmjs.org/vue/-/vue-0.8.6.tgz but it does not exist on npm and returns a 404.

{{< imgcap title="Vue.js 0.8.6 tarball not found" src="06-vue-not-found.png" >}}

Which means `HEAD` will not have a `Content-Length` header (or `0` if we are unmarshalling the response into a struct).

{{< imgcap title="HEAD on Vue.js 0.8.6 tarball" src="07-vue-not-found-head.png" >}}

# Why does it Work for tarballs?
Now you could say this method will work for most files and you would be correct. But `tar.gz` files are different.

Let's assume you want to modify a JavaScript file without altering the size. Remove comments, whitespace etc and add your own code. One character removed for every character added. If it's done to multiple files in the package, the total size of files will stay the same. If you `tar` them, they are all concatenated into one big file. `tar` of the modified version and the original version will have the same size (I think).

That's when `gzip` jumps in. It's a compression tool, uses dictionaries and everything. It's going to be impossible to have modified files that produce the same size after compression. The dictionary and other artifacts will be different.

# Conclusion
This is a nice trick. I explained it to a group recently and was asked why I did not download the files instead. I felt damn clever after explaining it. Let me have my moment.