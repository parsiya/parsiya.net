---
title: "So You Wanna Use Your Own LLMs in GitHub Copilot Chat"
date: 2025-09-03T07:00:00-07:00
draft: false
toc: true
twitterImage: 
url: /blog/litellm-ghc-aad
categories:
- AI
---

We want to use custom OpenAI compatible API LLMs with GitHub Copilot Chat in VS
Code without API keys. We will use LiteLLM as a proxy for authentication and use
the Azure AI model support in Chat as a hack.

<!-- More -->

# Problem Statement
GitHub Copilot Chat in VS Code (moving forward, called `Chat`[^1]) allows custom
LLM deployments, but only supports API keys and not AAD/Entra ID. API keys are
icky and [not cool anymore][sfi-secrets]. Using this method I can:

1. Use my own deployment in Azure AI.
2. Use ~~AAD~~ Entra ID (placeholder for the eventual name change in 5 years).
3. As a bonus, decouple my code from LLM authentication.

[^1]: This also opens up fun possibilities like `Chat, is this true?`

[sfi-secrets]: https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/secure-future-initiative-protect-identities-and-secrets.pdf

# Summary
If you just want the solution:

1. Create your own deployment in Azure AI.
2. Setup LiteLLM with a config like this:
   ```yaml
   general_settings:
     # master_key: sk-local-proxy # optional, fake API key for LiteLLM
     telemetry: false
   model_list:
     - model_name: "gpt-5-parsia" # custom name that GitHub Copilot chat sees
       litellm_params:
         model: "azure/gpt-5-parsia" # keep "azure/", the rest is the name of the deployment
         api_base: "https://{base-api}.cognitiveservices.azure.com/" # replace
         api_version: "2024-12-01-preview" # replace if needed
   litellm_settings:
     enable_azure_ad_token_refresh: true # use AAD tokens
     drop_params: true # keep this, otherwise you will get errors.
   ```
3. Add this section to the VS Code config:
  ```json
  {
    // rest of the settings
    "github.copilot.chat.azureModels": {
      "gpt-5-parsia": { // This is just an identifier
        "name": "gpt-5-parsia",   // The model name you see in Chat
        "url": "http://localhost:4000/v1/chat/completions", // Point to LiteLLM
        "maxInputTokens": 128000, // Set based on your model
        "maxOutputTokens": 16000, // Ditto
        "toolCalling": true,      // Enable this
        "vision": false,
        "thinking": false
      }
    }
  }
  ```
1. Create this env variable for LiteLLM:
  1. `AZURE_CREDENTIAL` with value `DefaultAzureCredential`
2. Run LiteLLM
  1. `litellm --config .\config.yaml --host localhost`
3. Click `Manage Model` in Chat and select `Azure`.
4. Choose `gpt-5-parsia`.

Drawback: There's a very noticeable lag in responses compared to the built-in
models. Not that bad if you're batch processing, but not a great experience for
real-time use.

# Details
While I like the models in Chat, using your own model in your own subscription
opens up a lot of opportunities. I was talking to a friend at work (you've been
promoted to friend for external propaganda purposes, A) and they mentioned not
using the built-in models in Chat because of dealing with sensitive stuff (OMG,
who cares, donate it all to the magic oracle in return for visions).

Chat has support for Azure models (and other providers), but only supports API
keys. We cannot use API keys. With apologies to [Hafez][hafez]:

> دردم از کار است و درمان نیز هم [^2]
> My pain and remedy are both from work

[hafez]: https://en.wikipedia.org/wiki/Hafez

[^2]: The original verse is "دردم از یار است و درمان نیز هم" (My pain and remedy are both from the beloved). Replacing یار (beloved) with کار (work).

So I am logged into the machine which is Entra joined, and my model is deployed
in Azure, so I should be able to get a token to talk to the model, but Chat
doesn't support this natively.

## Enter LiteLLM
At DEF CON, I visited AIxCC and briefly talked with people. Looking through the
code for Trail of Bits 2nd place system, [ButterCup][bt], I saw a directory
named [litellm][bt-lite].

[bt]: https://github.com/trailofbits/buttercup
[bt-lite]: https://github.com/trailofbits/buttercup/tree/main/litellm

[LiteLLM][litellm-main] is a local LLM proxy. It does a lot more like budgeting,
but I was only interested in [Azure AD Token Refresh][litellm-ad] support. It
uses something called `DefaultAzureCredential` to obtain a token. 

[litellm-main]: https://docs.litellm.ai/docs/
[litellm-ad]: https://docs.litellm.ai/docs/providers/azure#azure-ad-token-refresh---defaultazurecredential

Think of `DefaultAzureCredential` as a magical way of getting an AAD token. On
an Entra-joined machine, it will try a few ways to passively obtain a valid token
and if not, will show you one of those familiar "choose account" dialogs and if
all else fails, opens a browser window to let you login [^3].

[^3]: It really doesn't matter what it does behind the scenes. It's a magical token-granting wishing well.

So we create a LiteLLM config like this:

```yaml
# Basic proxy settings
general_settings:
  # master_key: sk-local-proxy # optional, fake API key for LiteLLM
  telemetry: false

model_list:
  - model_name: "gpt-5-parsia" # custom name that GitHub Copilot chat sees
    litellm_params:
      model: "azure/gpt-5-parsia" # keep "azure/", the rest is the name of the deployment
      api_base: "https://{base-api}.cognitiveservices.azure.com/" # replace
      api_version: "2024-12-01-preview" # replace if needed
    model_info: # optional section but helps LiteLLM understand things
      base_model: "gpt-5"
      mode: "completion" # not needed but good to have
      # more options
      # input_cost_per_token
      # output_cost_per_token
      # max_tokens
      # metadata # apparently freeform!

# Optional router/proxy tweaks
router_settings:
  num_retries: 2
  timeout: 120

litellm_settings:
  enable_azure_ad_token_refresh: true # this is where the AAD token is magically acquired
  drop_params: true # keep this, otherwise you will get errors.
```

Most of the config is self-explanatory. You can have multiple models in LiteLLM.
Our example only has one. You only need to replace a maximum of
three items under `litellm_params` with data from your deployment.

1. `model`: This should start with `azure/` to tell LiteLLM where it's hosted.
2. `api_base`: Your API endpoint. This is
   `https://{base-api}.cognitiveservices.azure.com/` where `{base-api}` is also
   the name of your Azure AI Foundry resource.
3. `api_version`: Comes from your deployment.

The config is very extensive. For example, LiteLLM can create fake API keys
with specific budgets. These are used to talk to LiteLLM. You can also have a
set API key for Chat to talk to LiteLLM (top of the config).

Now, we can run LiteLLM and it will expose an OpenAI compatible API (e.g.,
`/chat/completions/`) which is the de facto standard these days. But we have
more work to do.

## Chat's Ollama Support
Chat supports local models, but via [Ollama](https://ollama.com/). By default,
it tries to talk to `http://localhost:11434`; you can also change it with
this key in the VS Code config.

```json
"github.copilot.chat.byok.ollamaEndpoint": "http://localhost:11434",
```

So we can tell Chat to talk to a custom endpoint. However, Chat is expecting an
Ollama API which is different from OpenAI compatible API exposed by LiteLLM and
used by Azure.

[You Can Now Connect Your Own Model for GitHub Copilot][li] from March 2025
suggests running LiteLLM on `11434` and claims it can emulate an Ollama API. I
couldn't get it to work, and I could not find any switches or configurations to
tell LiteLLM to emulate the Ollama API.

[li]: https://www.linkedin.com/pulse/you-can-now-connect-your-own-model-github-copilot-aymen-furter-qxwdf/

So we need something to translate one to the other. Originally, I used a second
Python package named [oai2ollama][oai] that does it. So the setup looked like
this:

[oai]: https://github.com/CNSeniorious000/oai2ollama

```
 .-------.      .----------.      .-------.      .--------.
| VS Code +--->| oai2ollama +--->| LiteLLM +--->| Azure AI |
 '-------'      '----------'      '-------'      '--------'
```

## Chat's Azure AI Support
There's experimental support for custom Azure AI models in VS Code's Chat. If
you open settings with `ctrl+,`, you can search for `Azure custom` and see it.
You have to edit it in JSON mode and add this info.

```json
{
  // rest of the settings
  "github.copilot.chat.azureModels": {
    "gpt-5-parsia": { // This is just an identifier
      "name": "gpt-5-parsia",     // The model name you see in Chat
      "url": "http://localhost:4000/v1/chat/completions", // Point to LiteLLM
      "maxInputTokens": 128000, // Set these based on your model
      "maxOutputTokens": 16000, // Ditto
      "toolCalling": true,      // Enable this
      "vision": false,
      "thinking": false
    }
  }
}
```

## Workflow

1. Run LiteLLM
  ```
  litellm --config config.yaml --host localhost
  ```
2. In VS Code's Chat, click the model and select `Manage Models`.
3. Select Azure and you should see your model.
4. If Chat asks for an API key, enter any random text unless you had set up one
   in LiteLLM's config. This will only be sent to LiteLLM.

You should disable all other Copilot models in Chat to ensure you're only using
the AI in your own subscription. The model might change when you start a new
instance of VS Code.

1. In Chat, click on `Manage Models`.
2. Select `Copilot` and remove all models.
3. Repeat for any other model you've setup.

## Benefits
Now you have your own private hallucinating oracle that grants wishes in a
secure manner.

For me, the main benefit is separating my models, authentication, and tokens
from code. In the code, I just need a model name and endpoint and to quote
[Billy Connolly's HBO skit][hbo] "buggered if I know what happens after
that[^4]."

[hbo]: https://youtu.be/uPxKW7RR7h0?t=169

[^4]: Hafez to Billy Connoly is quite the transition. Enjoying this "diversity of thought?"

## Drawbacks
It's SLOW with a very high latency of 30-40 seconds (GPT-5). And I'm not talking
about just the first request that needs to acquire a token. Subsequent requests
also have this high lag and it makes GPT-5 unusable for real time use, but it
works for batch processing as long as you are not sending more than dozens of
requests per second.

IMO, part of the latency is because GPT-5 is only available in East US2 which is a
bit away from me in PNW. See [Global Standard model availability][gl] for more
info.

**Experiment #1**: GPT-4.1 in WestUS3 has a ~3 second delay which is on par with
built-in models in Chat and quite usable.

[gl]: https://learn.microsoft.com/en-us/azure/ai-foundry/openai/concepts/models?tabs=global-standard%2Cstandard-chat-completions#global-standard-model-availability

Another issue is that LiteLLM loads tons of features that we do not use.

**Future work #1**, I need to find a similar product. I've looked into Portkey,
but I haven't experimented with it yet. Theoretically, you could code something
that refreshes the token and redirects the requests, but I'd rather use an
existing product in case I want to use other endpoints.

## Q&A

1. Does it work in Visual Studio?
    1. I don't know. I use VS Code. I am a normie, not a corpo.
2. Why doesn't GitHub Copilot Chat have this functionality?
    1. Good question. I think it's a good use case. Apparently, there's a new
     extension API in vscode-insiders that can be used to implement this
     functionality.

As usual if you have any better solutions, you know where to find me.
