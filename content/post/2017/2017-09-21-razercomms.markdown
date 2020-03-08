---
title: "Razer Comms"
date: 2017-09-21T22:45:20-04:00
draft: false
toc: true
comments: true
categories:
- Razer Comms
- Thick Client Proxying
- Writeup
tags:
- proxy
- CEF
- Burp
---

A couple of years ago I looked at Razer Comms. I found a bunch of stuff that I never reported or pursued. I discovered the application is [now retired](http://support.razerzone.com/software/comms) so I am publishing these.

I did not look very hard but Razer Comms was essentially a webapp running via the [Chromium Embedded Framework](https://bitbucket.org/chromiumembedded/cef). There were no checks on channel authorizations. You could read every channel including ones protected with passwords.

You can see my notes at https://github.com/parsiya/Parsia-Clone/tree/master/research/razer-comms.

<!--more-->

# Mini Report
These are some of the stuff that I found. I wish I had looked into some of the stuff more. Especially the parts about what could be done when I got XSS.

At work I provide similar information in my report because I think `Steps to Reproduce` are an important part of any report. The client, dev team and the next person who comes for the next iteration of the app need to be able reproduce what I did.

## 1. Stored Cross-Site Scripting in Community Chat Channels (both application and web chatrooms)
The Razer Comms application does not perform any kind of input validation or sanitization on user input in community chat channels. This leads to stored cross-site scripting in community chats in the application, in-game overlay and in the web interface.

Community chat channels utilize both HTTP based requests and an XMPP server (located at `comms-cxmpp.razersynapse.com:5222`) using WebSockets to post and retrieve messages. Based on observation it seems that XMPP is used to provide the real-time chat while the messages sent through HTTP are actually stored on the server. For example if different messages are sent with the same message ID to the server via the XMPP protocol and a PUT request, the XMPP message is displayed instantly while the message sent via the PUT request is stored on the server and later displayed when the chat room is reloaded or if any user joins the channel after the message is posted.

The message is wrapped in `<span>` tags and sent to the server (in both XMPP and HTTP) and is reflected back as-is. The application uses [Chromium Embedded Framework](https://bitbucket.org/chromiumembedded/cef) or CEF to display community chats which are essentially HTML pages with CSS to display the messages. Each community chat room is also available through a web portal using the same HTML structure.

The JavaScript is not able to escape the CEF (although it is run with the `--no-sandbox` command line parameter) and modify anything in the application. However, it is possible to inject malicious JavaScript to trick users into entering their password or make the chat channels unusable. It is also possible to inject HTML to display spoofed messages (e.g. messages displayed from a different user such as an administrator to direct users to use a malicious website).

The chat web interface has the same issue. Each community's chatroom is also available via web at the `https://comms.razerzone.com/communities/chatpanel/index.html?id={{communityID}}` URL. XSS payloads are executed in users' browsers if they navigate to the web-based chatrooms.

User's can access chat channels from the in-game overlay. The in-game overlay does not execute all JavaScript. For example alert boxes are not displayed but they prevent users from viewing or posting anything in chat via the in-game overlay making them unusable.

**Steps to Reproduce (simple JavaScript prompt injected from the application):**

1. Setup Burp as proxy.
2. Login to the application.
3. Join any community chat, during the testing a private password protected community chat was created.
4. In Burp, turn on the interception functionality via `Proxy (menu) > Options (sub-menu) > Intercept is On (button)`.
5. Post anything in the chat channel.
6. In Burp, observe the WebSocket connections to get a message ID from the XMPP server. Forward them without modification.
    {{< imgcap title="XMPP chat message sent to server" src="/images/2017/razercomms/01-XSS-1.png" >}}
7. Look for the `PUT` request to the following URL with the message in its body:
    - https://api.comms.razerzone.com/communities/{{communityID}}/channels/{{chatroomID}}/messages/{{messageID}}
    {{< imgcap title="PUT request containing the chat message intercepted in Burp" src="/images/2017/razercomms/02-XSS-2.png" >}}
8. Modify the payload to `<script>prompt('Please enter your password', 'Password')</script>` and disable Burp interception by clicking the `Intercept is On` button.
    {{< imgcap title="Intercepted PUT request modified in Burp" src="/images/2017/razercomms/03-XSS-3.png" >}}
9. In the application observe the chat channel is still displaying the original payload (`test`) sent via XMPP.
    {{< imgcap title="Chat channel before reloading" src="/images/2017/razercomms/04-XSS-4.png" >}}
10. Close the community chat window and rejoin.
11. Observe the prompt indicating that injected JavaScript was executed.
    {{< imgcap title="Injected JavaScript executed after reloading" src="/images/2017/razercomms/05-XSS-5.png" >}}
12. Login to the community chat's web interface and observe the executed JavaScript.
    {{< imgcap title="Injected JavaScript in web interface" src="/images/2017/razercomms/06-XSS-6.png" >}}
13. Right click on the last chat message and select `Inspect Element` (or a similar item based on the browser) to view the injected JavaScript.
    {{< imgcap title="Web interface XSS source" src="/images/2017/razercomms/07-XSS-7.png" >}}

**Steps to Reproduce (simple JavaScript prompt injected from the web interface):**

1. Setup your browser to use Burp as proxy.
2. Login to the web interface for the community chat rooms using the following URL: `http://comms.razerzone.com/communities/preview/?id={{communityID}}`.
3. In Burp, turn on the interception functionality via `Proxy (menu) > Options (sub-menu) > Intercept is On (button)`.
4. Post anything in the chat channel.
5. In Burp, observe the WebSocket connections to get a message ID from the XMPP server. Forward them without modification.
6. Look for the `PUT` request to `https://api.comms.razerzone.com/communities/{{communityID}}/channels/{{chatroomID}}/messages/{{messageID}}` with the message in its body.
7. Modify the payload to `<script>prompt('Please enter your password', 'Password')</script>` and disable Burp interception by clicking the `Intercept is On` button.
8. Notice that the chat channel is displaying the original payload (`test`) sent via XMPP.
9. Refresh the web page and observe the injected JavaScript.

**Steps to Reproduce (Wreck chat channels)**

1. Follow the same steps above but inject the following payload:
    - `123</span></p></div>HELLO`
2. Note there are no messages visible and the message input field is gone.
    
{{< imgcap title="Community chat unusable" src="/images/2017/razercomms/08-chatdos.png" >}}

----------

## 2. Stored Cross-Site Scripting in User Profiles
The `Location/City` field in user profile is vulnerable to stored cross-site scripting (XSS). User profile is essentially a HTML page which is displayed in a browser using Chromium Embedded Framework (CEF) similar to chat rooms. Any injected JavaScript in the `Location/City` field will be executed in Razer Comms when that profile is viewed.

The following fields do not accept arbitrary input. For example `age` only accepts numbers so I could not inject anything malicious:

* Age
* Gender
* Language
* Location

Server performs input validation on the following fields. For example everything between angle brackets is removed:

* Name (first name + last name)
* Nickname

Server performs output encoding on the following field. Angle brackets are encoded to `&lt;` and `&gt;`:

* about-me (status)

A sample request for modifying the user profile:

``` xml
POST /1/user/post HTTP/1.1
Content-Type: application/xml
Host: ecbeta.razerzone.com
Content-Length: 940
Connection: close

<COP>
  <User>
    <ID>RZR_ID</ID>
    <Token>[token removed]</Token>
    <LastName access="private">lastname</LastName>
    <FirstName access="private">firstname</FirstName>
    <Nickname>user2</Nickname>
    <BirthYear access="private">1980</BirthYear>
    <BirthMonth access="private">1</BirthMonth>
    <BirthDay access="private">1</BirthDay>
    <Gender access="private">Female</Gender>
    <City access="private">location</City>
    <Country access="private">AL</Country>
    <UserLanguage access="private">en</UserLanguage>
    <AboutMe>status</AboutMe>
  </User>
  <ServiceCode>0020</ServiceCode>
</COP>
```

Note: Because profile data are sent in an XML payload through the body of the `PUT` request, injection payloads containing special characters need to be smuggled in a `CDATA` tag:

- `<![CDATA[<script>alert(1)</script>]]>`


Part of the profile:

```html
<body oncontextmenu="return false;">
<div id="body">
  <div id="section-header" class="about-slider">ABOUT</div>
  <div id="inner-data" class="about-sliding-div">
    <table id="avatar-about-me" border="0" cellspacing="0" cellpadding="0">
      <tr>
        <td class='fade' id='status-icon'>
          <img width='6' height='70px' src='images/status/online.png'/>
        </td>
        <td class="fade" id="avatar"><img width="70" height="70" src="images/avatar.png"/></td>
        <td id="name-about-me">
          <div class="fade1 ellipsis_div" id="name">firstname lastname</div>
          <div class="fade1 ellipsis_div about-wrap" id="about-me">"status1&lt;script&gt;alert(1)&lt;/script&gt;"</div>
        </td>
      </tr>
    </table>
    <div style="margin-top:12px"></div>
    <div id="info-div">
      <table id="info-table">
        <tr id="info-row">
          <td id="info-header" scope="row">Nickname</td>
          <td class="fade2" id="info-data"><div class="ellipsis_div">nickname</div></td>
          <td></td>
        </tr>
        <tr id="info-row">
          <td id="info-header">Comms ID</td>
          <td class="fade3" id="info-data-razer-id"><div class="ellipsis_div">comms ID</div></td>
        </tr>
        <tr id="info-row">
          <td id="info-header">Date of Birth</td>
          <td class="fade4" id="info-data"></td>
        </tr>
        <tr id="info-row">
          <td id="info-header">Age</td>
          <td class="fade5" id="info-data"></td>
        </tr>
        <tr id="info-row">
          <td id="info-header">Gender</td>
          <td class="fade6" id="info-data"></td>
        </tr>
        <tr id="info-row">
          <td id="info-header">Language</td>
          <td class="fade7" id="info-data"><div class="ellipsis_div">English</div></td>
        </tr>
        <tr id="info-row">
          <td id="info-header">Location</td>
          <td class="fade8" id="info-data"><div class="ellipsis_div"></div></td>
        </tr>
      </table>
    </div>
  </div>
```

**Steps to Reproduce:**

1. Setup Burp as proxy.
2. Login to the application.
3. Click on username and from the drop-down menu select `EDIT PROFILE`.
4. In Burp, turn on the interception functionality via `Proxy (menu) > Options (sub-menu) > Intercept is On (button)`.
5. Set access level of all fields to at least `Friends` and close the window. Remember to fill in at least `Location` and `Country`, otherwise the access level for those fields will not be modified.
6. In Burp, look for the `PUT` request to `https://ecbeta.razerzone.com/1/user/post`.
7. Modify the `City`, `FirstName`, `LastName` and `Nickname` fields to `<![CDATA[<script>alert(1)</script>]]>` and turn off Burp's interception functionality (this will forward the modified request).
8. Login to the application using a second user and add the first user as friend.
9. Right click on the first user and select `View Profile`.
10. Observe the alert box.

{{< imgcap title="XSS in profile" src="/images/2017/razercomms/09-XSS-8.png" >}}

------

## 3. Spoofing Sender via XMPP
The XMPP server does not check if the person sending the message is the same as the one in the message. Messages can be spoofed to have come from anyone. But XMPP is only used to present chatrooms' realtime functionality. Messages stored on the server are the ones sent by the `PUT` requests and are stored server-side. As a result it's only possible to spoof messages in realtime and not stored.

**Steps to Reproduce:**

1. Setup Burp as proxy.
2. Login to the web interface or use the Razer Comms application to join a community.
3. In Burp, turn on the interception functionality via `Proxy (menu) > Options (sub-menu) > Intercept is On (button)`.
4. Enter a message in chat and press Enter.
5. In Burp, look for the first request which should be an XMPP message via a websocket.
    {{< imgcap title="Intercepted chat message sent via websocket" src="/images/2017/razercomms/10-XMPP-spoof-1.png" >}}
6. Modify the `sender_name` element.
    {{< imgcap title="Sender name modified in intercepted request" src="/images/2017/razercomms/11-XMPP-spoof-2.png" >}}
7. Turn off the interception functionality in Burp.
8. Observe the message in the chat channel displayed as it's coming from the modified sender.
    {{< imgcap title="Message with the spoofed sender name" src="/images/2017/razercomms/12-XMPP-spoof-3.png" >}}
9. Rejoin the chat channel to observe that the stored message (the one sent with the `PUT` request) has the correct sender name.
    {{< imgcap title="Stored message after refresh displays the correct sender name" src="/images/2017/razercomms/13-XMPP-spoof-4.png" >}}

------

## 4. Lack of Authorization Controls
The Razer Comms server seems to lack authorization controls for many actions. For example any user can access the contents of any password protected channel or post messages to it. Or create a sub-channel without permissions. This is dangerous as users can do all of this by knowing communityIDs and channelIDs which are not secret and can be retrieved by any user.

Fortunately it is not possible to delete communities as a normal member. The communities are deleted using the `DELETE` HTTP method and normal members receive a `403 Forbidden` response when attempting to delete communities without having access.

{{< imgcap title="Communities cannot be deleted" src="/images/2017/razercomms/14-community-delete.png" >}}

![](community-cannot-be-deleted.PNG)

The server does not perform any authorization checks for read/post requests to password protected chat channels. Any user can read the contents of them and/or post messages. The only information needed for these actions are communityIDs and channelIDs which are public information. Any user can query a specific community and retrieve channel IDs.

For this test, two users were created. One user created a private community. Within the community a password protected channel is created. Another user is invited to the community and joins. The second user should not be able to view the contents of the password protected channel and post to it without knowing the channel password.

**Steps to Reproduce (posting messages and reading the contents of a password protected channel):**

1. Setup Burp as proxy.
2. Login to the application as a user with access to a community with a password protected channel but without access to it.
3. Join the aforementioned community and enter the lobby.
    {{< imgcap title="Joining a community with a password protected channel" src="/images/2017/razercomms/15-password-1.png" >}}
4. In Burp, find the GET request to the following URL:
    - https://api.comms.razerzone.com/communities/{{communityID}}/channels?api_key={{API_Key}}.
    {{< imgcap title="The request to join the lobby" src="/images/2017/razercomms/16-password-2.png" >}}
5. Click on the `Response` tab to view the response to this request. The response contain the lobby ID.
    {{< imgcap title="Lobby ID" src="/images/2017/razercomms/17-password-3.png" >}}
6. Because each channel is a sub-channel of lobby, the next request will retrieve all sub-channels. It's a GET request to https://api.comms.razerzone.com/communities/{{communitID}}/channels/{{lobbyID}}/channels?api_key={{API_Key}}. Right click and select `Send to Repeater` from the context menu.
    {{< imgcap title="Request that retrieves all sub-channels" src="/images/2017/razercomms/18-password-4.png" >}}
7. The response to this request contains all channelIDs including the password protected channel. Notice the properties of the channel (`"protected": true`).
    {{< imgcap title="ID and properties of the password protected channel" src="/images/2017/razercomms/19-password-5.png" >}}
8. Switch to the Burp Repeater tab.
9. In Burp Repeater, modify the GET request to the following: https://api.comms.razerzone.com/communities/{{communityID}}/channels/{{passwordProtectedChannelID}}/messages and send the request.
10. Observe that you can read all messages in the password protected channel.
    {{< imgcap title="Retrieving posts in the password protected channel" src="/images/2017/razercomms/20-password-6.png" >}}
11. Turn on Burp's interception functionality via `Proxy (menu) > Options (sub-menu) > Intercept is On (button)`.
12. Post something in the lobby.
13. Forward all requests until the `PUT` request to https://api.comms.razerzone.com/communities/{{communitID}}/channels/{{channelID}}/messages/{{messageID}}.
    {{< imgcap title="Intercepted chat message request" src="/images/2017/razercomms/21-password-7.png" >}}
14. Modify the channelID to the password protected channel ID and forward the request by turning off the interception functionality. Message content can also be modified.
    {{< imgcap title="Modified chat channelID to point to the password protected channel" src="/images/2017/razercomms/22-password-8.png" >}}
15. Switch back to the Repeater tab and resend the previous modified request to read all messages in the password protected channel.
    {{< imgcap title="Message posted to the password protected channel" src="/images/2017/razercomms/23-password-9.png" >}}    
16. Alternatively login to the application as the community owner and view the posted message in the password protected channel.
    {{< imgcap title="Message posted to the password protected channel" src="/images/2017/razercomms/24-password-10.png" >}}    

---------

## 5. Internal Server IP Leaked
Responses leak internal IPs.

* 10.101.152.28
* 10.180.204.132
* 10.147.221.244

{{< imgcap title="Internal IPs in responses" src="/images/2017/razercomms/25-internal-ip.png" >}}



