# mqirc
MQTT Shell to IRC Bridge 

## About

<p>This is an irc bridge for mqtt shells. By default, program tries to detect whether or not you are using base64 and json and will figure it out, but if you want to send messages in base64, specify -b flag at startup. </p>

<p>This was written for use with mqtt shells, but you can use it for pretty much any situation where you want to interact with mqtt over irc.</p>

## [\*Note] about JSON:
<p> If you want to parse json replies from your mqtt subscribed topic, than you need to edit the json fields you want to display. If you are not using json, than don't worry about this.</p>


## What's New:
 
 Version 2.2:
 
 - Added logging and better nick/user/ident parsing for security
 - Added library for easy irc color/string formatting
 - Added local shell interface
 - Added a bash wrapper to start, stop, and restart mqirc
 - Other Minor changes
 
Previous version:
 
 - Merged config file parsing: get args from both/either the command line and/or a configuration file
 - Clean up argparse
 - Add user access controls (to whitelist users and channels)
 - Fix single quote parsing for outgoing messages
 - Fix broken user mode synax (sorry, my bad)
 - Other minor fixes

## Requirements:

- paho-mqtt<br> 
 --install on linux : pip install paho-mqtt <br>
 -- alternatively: pip install -r requirements.txt<br>
## Demo:
<pre>
08:53 -!- mqirc [~mqirc@127.0.0.1] has joined #mqtt
08:53 <@anon> @help
08:53 < mqirc> ======== MQIRC Version 1.4 Beta Bot Commands ========
08:53 < mqirc> Bot responds to the following commands
08:53 < mqirc> @cmd <message> : Send a message to pubtopic
08:53 < mqirc> @help : Show this help
08:53 < mqirc> @die : Shut down bot
08:53 < mqirc> @echo <string> : Echo a message
08:53 < mqirc> @shell <command> : Execute a local shell command
08:53 < mqirc> ======= Authentication Commands ========:
08:53 < mqirc> @enable <password> : Authenticate to and enable the boT
08:53 < mqirc> @disable <password> : Lock bot. When disabled will only respond to @help
08:53 < mqirc> @userlist : Send list of authorized senders
08:53 < mqirc> @adduser <user/#channel> : Append nick/channel to authorized senders
08:53 < mqirc> @deluser <user/#channel> : Remove nick/channel from authorized senders
08:53 < mqirc> ======== IRC Commands ========:
08:53 < mqirc> @irc : <command> : Send a raw irc command to server
08:53 < mqirc> @register <password> <email> : Register bot with nickserv
08:53 < mqirc> @join : <channel> : Join this channel
08:53 < mqirc> @part : <channel> : Leave this channel
08:53 < mqirc> ======== ========= ========
08:53 <@anon> @enable mqirc
08:53 < mqirc> Sucess. System ready.
08:53 <@anon> @echo "Hello, World!"
08:53 < mqirc> "Hello, World!"
08:54 <@anon> @cmd uptime
08:54 < mqirc> '192.168.99.3' ' 08:57:07 up 3 days, 12:41, 20 users,  load average: 1.93, 1.93, 1.78'
08:54 < mqirc> '192.168.99.6' ' 05:26:05 up 2 days, 12:41, 10 users,  load average: 0.89, 0.93, 0.78'
08:54 < mqirc> '192.168.99.7' ' 01:33:04 up 1 days, 12:41, 13 users,  load average: 2.02, 2.93, 2.58'
08:54 <@anon> @userlist
08:54 < mqirc> Current whitelisted channels and users
08:54 < mqirc> ['shellz', 'kek', '#mqtt', 'anon']
08:55 <@anon> @die
08:55 < mqirc> Shutting down...
08:55 -!- mqirc [~mqirc@127.0.0.1] has quit [Client closed connection]
</pre>

## Usage:

- To bridge mqtt traffic on your localhost from topic shell/incoming and to topic shell/outgoing ,<br>
  to an irc server in channel #mqtt:<br>
  `python mqirc -s  'shell/outgoing' -t  'shell/incoming' -m localhost -c '#mqtt' -i localhost -I 6667`
- Authenticate with bot: @enable password (default password :mqirc , set with -K passwordhere)
- Add your nick and channels to `auth_users` whitelist array before first run (default: shellz, #mqtt)
- To send a message, "@cmd message to send here>"
- To get usage, "@help'
- To kill the bot, "@die"
- To join a channel, "@join #channel"
- To part a channel, "@part <#channel>"
- To make the bot say something, "@echo something"
- To register with nickserv, "@register password email"
- To send a raw irc command (example: send a privmsg), "@irc PRIVMSG somebody :hello, somobody!"

## Caveats:

- You may need to configure your irc server to not kick floods if you have a lot of clients (for unreal, compile with fakelag configurable)
- Everything else is fixed, so you tell me!
## TODO:

- implement irc tls
- implement mqtt tls
- add options to change/specifiy topics while running

<pre>
                                              _..._     
                   .-''-.                    .-'_..._''.  
 __  __   ___     //'` `\|   .--.          .' .'      '.\ 
|  |/  `.'   `.  '/'    '|   |__|         / .'            
|   .-.  .-.   '|'      '|   .--..-,.--. . '              
|  |  |  |  |  |||     /||   |  ||  .-. || |              
|  |  |  |  |  | '. .'/||   |  || |  | || |              
|  |  |  |  |  |  `--'` ||   |  || |  | |. '              
|  |  |  |  |  |        ||   |  || |  '-  \ '.          . 
|__|  |__|  |__|        || />|__|| |       '. `._____.-'/ 
                        ||//     | |         `-.______ /  
                        |'/      |_|                  `   
                        |/
                        
                   ~ MqTT-IRC Bridge ~
                       ShellzRuS 2017

Usage: mqirc.py [options]

Options:
  -h, --help            show this help message and exit
  -v, --verbose         Produce verbose output
  -d, --debug           Print debug messages
  -V, --very_verbose    Very Verbose mode: Print all raw output
  -S, --shell_enabled   Enable system shell (potentially dangerous!)
  -b, --base64_on       Base64
  -N, --notice          Respond to notices
  -C, --cleaner         Simplify output of mqtt json
  -m MQ_HOST, --mq_host=MQ_HOST
                        Mqtt host to connect to
  -p MQ_PORT, --mq_port=MQ_PORT
                        Mqtt port to connect to
  -u MQ_USER, --mq_user=MQ_USER
                        Mqtt user to auth with
  -P MQ_PASS, --mq_pass=MQ_PASS
                        Mqtt password to authenticate with
  -s MQ_SUBTOP, --mq_subtop=MQ_SUBTOP
                        Mqtt topic to subscribe to
  -t MQ_PUBTOP, --mq_pubtop=MQ_PUBTOP
                        Mqtt topic to publish to
  -i IRC_HOST, --irc_host=IRC_HOST
                        Irc host to connect to
  -I IRC_PORT, --irc_port=IRC_PORT
                        Irc port to connect to
  -n IRC_NICK, --irc_nick=IRC_NICK
                        Nick of irc user
  -c IRC_CHAN, --irc_chan=IRC_CHAN
                        Irc channel to join
  -k CHAN_KEY, --chan_key=CHAN_KEY
                        Channel key
  -a IRC_AUTH, --irc_auth=IRC_AUTH
                        Password to auth with nickserv
  -K BOT_KEY, --bot_key=BOT_KEY
                        Password to auth with bot
  -U PRIV_USER, --priv_user=PRIV_USER
                        Irc bot owner
</pre>

## License:
GPL Whatever, just credit me.
