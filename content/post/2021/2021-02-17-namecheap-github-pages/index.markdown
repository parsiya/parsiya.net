---
title: "Automagically Deploying Websites with Custom Domains to Github Pages"
date: 2021-02-17T09:56:33-08:00
draft: false
toc: false
comments: true
categories:
- Not Security
- Clone
- Automation
---

Recently, I have started moving my non-critical websites to Github pages. I am
documenting the process in one place for future me.

<!--more-->

## Objectives

1. I should be able to edit the website by committing to a git repository.
    1. We can also modify the blog using the web IDE if needed.
2. The system must generate the website after every push and deploy it to Github
   pages.
3. I want to use my own custom domain.

## Requirements

1. You have a custom domain. Mine are registered with Namecheap.
2. You either have a generated website or you can use a static
   website generator like [Hugo][hugo].
3. You have a Github account.

[hugo]: https://gohugo.io

## Github Project Sites
If you have a Github account (either user or organization) you can have a
website using Github pages at `your-account.github.io`. These are called user or
organization sites.

Each project in an account can have its own website. These are called `Project`
sites. They are available under `your-account.github.io/repository-name`.

We are going to leverage these project sites and deploy each project with a
custom domain.

For more info please see
[https://docs.github.com/en/github/working-with-github-pages/about-github-pages#types-of-github-pages-sites][github-pages-types].

[github-pages-types]: https://docs.github.com/en/github/working-with-github-pages/about-github-pages#types-of-github-pages-sites

## The Process
I am going to write this as concise as I can.

### Step 1: Change the DNS Records
You need to change the DNS records of your custom domain. This change is very
quick if your existing DNS is handled by Namecheap (e.g., a new domain) but it
took 24 hours for my AWS hosted websites.

If your domain has any existing DNS records, you need to delete them. This also
includes the default records pointing to the Namecheap parking page for new
domains.

One of my domains was hosted out of an S3 bucket so I had pointed the DNS
records to Amazon. In NameCheap, I had to switch the DNS back to `Namecheap
BasicDNS` under `Nameservers` in the `Domain` tab. This Namecheap KB article
shows how:

* [Why can't I modify Email, Domain Redirect, and Host Records in my Namecheap account?][namecheap-basic-dns]

[namecheap-basic-dns]: https://www.namecheap.com/support/knowledgebase/article.aspx/323/46/why-cant-i-modify-email-domain-redirect-and-host-records-in-my-namecheap-account/

After switching, we need to create five records. Four A records and a CNAME:

* A records with host `@` and the following values:
    * `185.199.108.153`
    * `185.199.109.153`
    * `185.199.110.153`
    * `185.199.111.153`
* CNAME record with host `www` and value `your-account.github.io.`.
    * **Note the extra dot in the end.** This is needed for project sites.

Reference: [https://deanattali.com/blog/multiple-github-pages-domains/][gh-pages-namecheap]

[gh-pages-namecheap]: https://deanattali.com/blog/multiple-github-pages-domains/

Namecheap has a guide for using user or organization Github pages. The process
is the same as above except the value of the CNAME record:

* [How do I link my domain to GitHub Pages?][namecheap-github-pages]

[namecheap-github-pages]: https://www.namecheap.com/support/knowledgebase/article.aspx/9645/2208/how-do-i-link-my-domain-to-github-pages/

### Step 2: Creating a Deploy Workflow
The workflow is pretty straightforward and based on this Hugo docs page:

* [https://gohugo.io/hosting-and-deployment/hosting-on-github/][hugo-host-github]

[hugo-host-github]: https://gohugo.io/hosting-and-deployment/hosting-on-github/

[begbounty.com][begbounty] is a simple single page Hugo website. But, it works
for more complex deployments.

You can see the workflow here:

* [https://github.com/parsiya/begbounty.com/blob/main/.github/workflows/gh-pages.yml][begbounty-workflow]

[begbounty]: https://begbounty.com
[begbounty-workflow]: https://github.com/parsiya/begbounty.com/blob/main/.github/workflows/gh-pages.yml

The `peaceiris-actions-hugo` action builds the Hugo website. If your website
does not need the extended version, be sure to remove the `extended: true`
field.

`peaceiris/actions-gh-pages` grabs the generated files from the `public`
directory and stores them in the `gh-pages` branch.

There is no need to setup the `secrets.GITHUB_TOKEN` token manually.

**Note:** I did not have this issue but the first deployment run might encounter
some issues and [you have to do re-run it][first-run].

[first-run]: https://github.com/peaceiris/actions-gh-pages#%EF%B8%8F-first-deployment-with-github_token

### Step 3: Push a Commit
We need to get the workflow to create the `gh-pages` branch. This is where you
can troubleshoot the site build. Clone the resulting branch locally to see how
the site looks like and fix any issues.

### Step 4: Repository Settings
Now, we need to setup the repository.

1. Go to the repository's `Settings` on Github.
2. Search the web page for `GitHub Pages`.
3. Under `Source` select the `gh-pages` branch.
4. Under `Custom domain` enter your domain. E.g., `begbounty.com`.
    1. This will create a file in the root of the repository named `CNAME` with
       value of `begbounty.com`. This is useless for a Hugo website but I chose
       to keep it.
    2. For Hugo websites, you should create it in `static/CNAME`. If you follow
       the instructions on the Hugo documentation page linked above, you already
       it.
5. Enable `Enforce HTTPS`. This will generate a certificate by `Let's Encrypt`.
   This is usually done in 15 minutes.

For more information please see this page on Github docs:

* [Configuring a custom domain for your GitHub Pages site][github-custom-domain]

[github-custom-domain]: https://docs.github.com/en/github/working-with-github-pages/configuring-a-custom-domain-for-your-github-pages-site

Now, you should be good to go. Fingers crossed.

#### A More Complex Workflow
For a more complex workflow for [parsiya.io][parsiya.io] (my clone) see this:

* [https://github.com/parsiya/Parsia-Clone/blob/main/.github/workflows/gh-pages.yml][parsiya.io-workflow]

[parsiya.io]: https://parsiya.io
[parsiya.io-workflow]: https://github.com/parsiya/Parsia-Clone/blob/main/.github/workflows/gh-pages.yml

This website is a bit special. The contents are in
[https://github.com/parsiya/Parsia-Clone][parsia-clone-github] but the actual
Hugo theme is in a different repository at
[https://github.com/parsiya/parsiya.io][parsiya.io-github].

I wanted to have the contents in a separate place without the theme. The
workflow checks out the `parsiya.io` repository first and then checks out
`parsia-clone` under the `content` directory.

[parsia-clone-github]: https://github.com/parsiya/Parsia-Clone
[parsiya.io-github]: https://github.com/parsiya/parsiya.io

While the theme has the content directory as a submodule, just populating the
submodule means I am looking an older commit so the new content are not pulled.
Hence, this in the workflow:

```yaml
- name: Checkout parsiya.io
uses: actions/checkout@v2
with:
    repository: 'parsiya/parsiya.io' # Get parsiya.io the parent repo
    submodules: true  # Fetch Hugo themes (true OR recursive)
    fetch-depth: 1    # Fetch all history for .GitInfo and .Lastmod

- name: Checkout parsia-clone # Otherwise the outdated commit will be pulled
uses: actions/checkout@v2
with:
    repository: 'parsiya/parsia-clone'
    path: 'content'
```

There appears to be some ways to make a submodule pull to get the latest commit.
I searched around the internet and realized a second checkout is not going to be
end of the world and is much simpler to accomplish.
