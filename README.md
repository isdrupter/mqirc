# mqirc
MQTT Shell to IRC Bridge 

## About

<p>This is an irc bridge for mqtt shells. By default, program tries to detect whether or not you are using base64 and json and will figure it out, but if you want to send messages in base64, specify -b flag at startup. </p>

<p>This was written for use with mqtt shells, but you can use it for pretty much any situation where you want to interact with mqtt over irc.</p>

## Requirements:

- paho-mqtt<br> 
 --install on linux : pip install paho-mqtt <br>
 -- alternatively: pip install -r requirements.txt<br>

## Usage:

- To bridge mqtt traffic on your localhost from topic shell/incoming and to topic shell/outgoing ,<br>
  to an irc server in channel #mqtt:<br>
  `python mqirc -s  'shell/outgoing' -t  'shell/incoming' -m localhost -c '#mqtt' -i localhost -I 6667`
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
- Currently does not properly parse single quotes in outgoing mqtt messages. This will be fixed soon, use double quotes instead for now.
## TODO:

- fix single quote parsing for outgoing mqtt messages
- implement irc tls
- implement mqtt tls
- add options to change/specifiy topics while running
- logging

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

usage: ircmq5.py [-h] [-m MQ_HOST] [-p MQ_PORT] [-u MQ_USER] [-P MQ_PASS]
                 [-s MQ_SUBTOP] [-t MQ_PUBTOP] [-i IRC_HOST] [-I IRC_PORT]
                 [-n IRC_NICK] [-c IRC_CHAN] [-k CHAN_KEY] [-a IRC_AUTH]
                 [-U PRIV_USER] [-d [DEBUG]] [-v [VERBOSE]]
                 [-vv [VERY_VERBOSE]] [-b [BASE64_ON]] [-N [NOTICE]]

optional arguments:
  -h, --help            show this help message and exit
  -m MQ_HOST, --mq_host MQ_HOST
                        Mqtt host to connect to
  -p MQ_PORT, --mq_port MQ_PORT
                        Mqtt port to connect to
  -u MQ_USER, --mq_user MQ_USER
                        Mqtt user to auth with
  -P MQ_PASS, --mq_pass MQ_PASS
                        Mqtt password to authenticate with
  -s MQ_SUBTOP, --mq_subtop MQ_SUBTOP
                        Mqtt topic to subscribe to
  -t MQ_PUBTOP, --mq_pubtop MQ_PUBTOP
                        Mqtt topic to publish to
  -i IRC_HOST, --irc_host IRC_HOST
                        Irc host to connect to
  -I IRC_PORT, --irc_port IRC_PORT
                        Irc port to connect to
  -n IRC_NICK, --irc_nick IRC_NICK
                        Nick of irc user
  -c IRC_CHAN, --irc_chan IRC_CHAN
                        Irc channel to join
  -k CHAN_KEY, --chan_key CHAN_KEY
                        Channel key
  -a IRC_AUTH, --irc_auth IRC_AUTH
                        Password to auth with nickserv
  -U PRIV_USER, --priv_user PRIV_USER
                        Irc bot owner
  -d [DEBUG], --debug [DEBUG]
                        Print debug messages
  -v [VERBOSE], --verbose [VERBOSE]
                        Verbose mode
  -vv [VERY_VERBOSE], --very_verbose [VERY_VERBOSE]
                        Very Verbose mode: Print all raw output
  -b [BASE64_ON], --base64_on [BASE64_ON]
                        Base64
  -N [NOTICE], --notice [NOTICE]
                        Respond to notices

</pre>

## License:
GPL Whatever, just credit me.
