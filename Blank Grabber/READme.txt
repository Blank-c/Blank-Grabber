Python 3.10 or above must be installed and added to path!
Internet connection must be available!
Disable your antivirus/defender as it might delete some important files!

Run "Builder.bat"

you can change CS2 with the C2 option on right.the default C2 is discord but you can also change it into telegram.
for discord C2- 
you need to make a discord webhook for it.
to make a discord webhook-

1: Open Discord and go to the server where you want to add the webhook. You need to have the necessary permissions (e.g., Manage Webhooks) on that server.

2: Right-click on the channel where you want the webhook to post messages and select "Edit Channel."

3: In the channel settings, click on the "Webhooks" tab, usually located on the left sidebar.

4: Click the "Create Webhook" button. A dialog box will appear.

5: Provide a name for your webhook. This will be the name that appears when the webhook sends the stolen info.

6: After providing a name, click the "Copy Webhook URL" button. This will copy the webhook URL to your clipboard.

7: Click the "Save" or "Create" button to create the webhook.

8: then put the webhook into the "Enter Discord Webhook URL with https://"

discord can ban your account for this so make a temporary account for discord. telegram doesnt ban your account though.

for telegram C2-
You need telegram endpoint for it.it consists of [Telegram bot toekn]&[Telegram chat id]
it could look like https://api.telegram.org/bot1234567890:ABCDEFGHIJKLMN
to make telegram endpoint-

Download the Telegram app:
If you don't have the Telegram app installed on your device, download it from your device's app store and create an account.

Create a new bot:
To create a new bot, you need to interact with the BotFather bot on Telegram. Search for "BotFather" in the Telegram app and start a chat with it.

Start the bot creation process:
Send the BotFather the command /newbot to start creating a new bot.

Provide a name and username for your bot:
The BotFather will ask you to provide a name for your bot. Choose a name that represents your bot. Next, you need to choose a unique username that ends with the word "bot." For example, if your bot name is "MyAwesomeBot," you can choose a username like "MyAwesomeBotBot."

Obtain your bot token:
After providing a name and username, the BotFather will generate a token for your bot. The token will be a long alphanumeric string that looks like 1234567890:ABCDEFGHIJKLMN. Save this token securely, as it will be used to authenticate your requests to the Telegram Bot API.

to get chatid of a group do this-

Install Telegram,
Create a Bot using the official telegram BotFather (it has a verified symbol next to it when you add it as a contact),
Follow the prompts, and finally copy it’s HTTP API Token,
Create a Group,
Add the Bot to it,
Select the Bot User from the Group members list,
Press the SEND MESSAGE button,
Send the User a message.
Retrieve the Chat ID from the chat data using this website - https://q3qkk.csb.app/
enter your [telegram bot token]&[chat-id]

after you got the C2 set up 
click on the options to select the things you want to steal!

stub settings-
Ping Me	- Pings @everyone when someone runs the stub.
Anti VM	Tries - its best to prevent the stub from running on Virtual Machine.
Put On Startup - Runs the stub on Windows starup.
Melt Stub  - Deletes the stub after use.
Pump Stub - Pumps the stub upto the provided size.
Fake Error - Create custom (fake) error.
Block AV Sites - Blocks AV related sites.
Discord Injection - Puts backdoor on the Discord client for persistence.
UAC Bypass - Tries to get administrator permissions without showing any prompt.

to unblock sites run this py file 
https://github.com/Blank-c/Blank-Grabber/blob/main/Blank%20Grabber/Extras/unblock_sites.py
