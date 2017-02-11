#!/usr/bin/env python
# -*- coding: utf-8 -*-
print("""
                                              _..._     
                   .-''-.                    .-'_..._''.  
 __  __   ___     //'` `\|   .--.          .' .'      '.\ 
|  |/  `.'   `.  '/'    '|   |__|         / .'            
|   .-.  .-.   '|'      '|   .--..-,.--. . '              
|  |  |  |  |  |||     /||   |  ||  .-. || |              
|  |  |  |  |  | \'. .'/||   |  || |  | || |              
|  |  |  |  |  |  `--'` ||   |  || |  | |. '              
|  |  |  |  |  |        ||   |  || |  '-  \ '.          . 
|__|  |__|  |__|        || />|__|| |       '. `._____.-'/ 
                        ||//     | |         `-.______ /  
                        |'/      |_|                  `   
                        |/
                        
                   ~ MqTT-IRC Bridge ~
                       ShellzRuS 2017
""")
import sys,socket,string,time,re,binascii,base64,operator,json,argparse
import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish

#### Ya, ya not supposed to use globals
global mq_host
global mq_port
global sub_topic
global pub_topic
global mq_user
global mq_pass
#### 
global irc_host
global irc_port
global irc_nick
global irc_chan
#global priv_user
global debug
CHANNEL=""
CHANNEL_=""
NICK=""
IDENT="mqirc"
REALNAME="mqirc"
HOST=""
PORT=''
pong_once=''
priv_user=""
data = ''

# Check if string is ;egit
def isAscii(s):
    return all(ord(c) < 128 for c in s)


# fix python's stupidity with base64
def b64encode(s, altchars=None):
    encoded = binascii.b2a_base64(s)[:-1]
    if altchars is not None:
        return _translate(encoded, {'+': altchars[0], '/': altchars[1]})
    return encoded
# check padding
def urlsafe_b64decode(s):
      s = str(s).strip()
      try:
          return base64.b64decode(s)
      except TypeError:
          padding = len(s) % 4
          if padding == 1:
              return ''
          elif padding == 2:
              s += b'=='
          elif padding == 3:
              s += b'='
          return base64.b64decode(s)

def parse_message(s):
    """Breaks a message from an IRC server into its prefix, command, and arguments.
    """
    prefix = ''
    trailing = []
    if not s:
       raise IRCBadMessage("Empty line.")
    if s[0] == ':':
        prefix, s = s[1:].split('', 1)
    if s.find(' :') != -1:
        s, trailing = s.split(' :', 1)
        args = s.split()
        args.append(trailing)
    else:
        args = s.split()
    command = args.pop(0)
    if debug:
        print ("Parsing message: \r\nPrefix: %s Args: %s Trailing: %s \n" %(prefix, args, trailing))
    return args

def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    client.subscribe(mq_subtop)

def on_message(client, userdata, msg):
    message = str(msg.payload)
    if verbose:
        print("Received message")
    if not base64_on:
        if debug:
            print("Not attempting base64 decode since -b was not specified")
        s.send("PRIVMSG %s :%s \n" %(CHANNEL, message))
    else:     
        try:
            decoded = urlsafe_b64decode(str(message))
        except Exception as e:
            if debug:
                print("Plaintext: %s" % message)
            if isAscii(message):
                s.send("PRIVMSG %s :%s \n" %(CHANNEL, message))
                return
        else:
            decoded = decoded.replace("\"bot version:", "\"bot version\":") # hack cause my json was invalid
            if debug:
                print(decoded)
            try:
                parsed_json = json.loads(decoded)
            except Exception as e:
                if debug:
                    print("Error %s" % e)
                #print(decoded)
                if decoded:
                    s.send("PRIVMSG %s :%s \n" %(CHANNEL, decoded))
            else:
                parsed_ip = (parsed_json['ip'])
                parsed_msg = (parsed_json['output'])
                #, 'status', 'cmdline', 'output' # some other example json fields
                if debug:
                    print("Parsed JSON: %s %s \n" %(parsed_ip, parsed_msg))
                s.send("PRIVMSG %s :%s %s \n" %(CHANNEL, parsed_ip, parsed_msg))
""" Connect to mqtt """
def connect_mqtt():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.connect(mq_host, mq_port, 60)
    client.username_pw_set(username=mq_user,password=mq_pass)
    client.on_message = on_message
    client.loop_start()
# publish mqtt message
def mqsend(message):
    # make the request, should give us back some JSON
    client = mqtt.Client()
    publish.single(mq_pubtop, payload=str(message), hostname=mq_host, port=mq_port,auth = {'username':mq_user, 'password':mq_pass})


#### Join channel, set modes
def join_irc(CHANNEL_):
    if debug:
        print("Joining %s" % CHANNEL_)
    s.send("MODE %s +xiw\r\n" % NICK)
    s.send("JOIN %s\r\n" % CHANNEL_)
    s.send("MODE %s +v \r\n"% NICK)

# Start the irc session
def connect_irc():
    if debug:
        print("Connecting to mqtt...")
    connect_mqtt()

    if verbose:
        print("Connecting to irc with nick %s ...\n" % NICK)
    s.send("NICK %s\r\n" % NICK)
    s.send("USER %s %s bla :%s\r\n" % (IDENT, HOST, REALNAME))
    time.sleep(2)
    join_irc(CHANNEL)

""" For future usage """
def part_chan(CHANNEL_):
    if verbose:
        print("Leaving channel %s" % CHANNEL_)
    s.send("PART %s \r\n" % CHANNEL_)
# Send usage
def bot_usage(action, recipitent):
    if debug:
        print("Sending as : %s " % action)
    s.send("%s %s : ==== MQIRC Bot Usage ====: \r\n" %(action, recipitent))
    s.send("%s %s : Bot responds to the following commands: \r\n" % (action, recipitent))
    s.send("%s %s : !cmd <message>: Send a message to pubtopic \r\n" % (action, recipitent))
    s.send("%s %s : !help : Show this help \r\n" % (action, recipitent))
    s.send("%s %s : !die : Shut down bot \r\n" % (action, recipitent))
    
#### Magic starts here
def listen_irc():
    readbuffer=""
    pong_once=0 # this is important! **
    while 1:
        
        readbuffer=readbuffer+s.recv(1000000)  
        temp=string.split(readbuffer, "\n")  
        #print (readbuffer)                   # Print raw output to screen        
        readbuffer=temp.pop( )
        for line in temp:
            line=string.rstrip(line)
            line=string.split(line)
            if(line[0]=="PING"):
                if verbose:
                    print("Received PING, sending PONG")
                s.send("PONG %s\r\n" % line[1])
                """ Some ircd's dont let you join a channel until after you reply with a pong (ie, ngircd) """
                pong_once+=1
                if (pong_once == 1):
                    join_irc(CHANNEL)
            elif (line[1]=="PRIVMSG" or line[1]=="NOTICE"):
                action=line[1]
                if verbose:
                    print("Received %s" % action)
                if debug:
                    print("Contents of received %s :\r\n %s" % (action, line))
                if action=="NOTICE":
                    recipitent = priv_user # todo: reply to user that sent the notice
                elif action=="PRIVMSG":
                    recipitent = CHANNEL
                if re.match(r'^:!cmd.*$', line[3]):
                    if verbose:
                        print("Received a command")
                    # gross code here, but functional
                    res = parse_message(str(line))
                    final = ''
                    for i in range(3, len(res)):
                        final = final + str(res[i])
                        print(i)
                        final = final.replace("'", "") # ugly ass hacks
                        final = final.replace(",", " ") # has trouble with commas and single quotes obviously
                    final = final[:-1]
                    
                    if debug:
                        print(final)
                    if verbose:
                        print("Publishing message")
                    if debug:
                        print("Parsing message with contents: \r\n %s " % final)
                    if base64_on:
                        if verbose:
                            print("Encoding message...")
                        final = b64encode(final)
                        if debug:
                            print("Encoded message: \r\n %s" % final)
                    try:
                        mqsend(final)
                    except Exception as e:
                        if verbose:
                            print("Failed to publish message!")
                        if debug:
                            print("Error:\n %s" % e)
                            
                elif re.match(r'^:!help.*$', line[3]):
                    if verbose:
                        print("Sending usage\n")
                    bot_usage(action, recipitent)
                elif re.match(r'^:!die.*$', line[3]):
                    if verbose:
                        print("Shutting down...")
                    s.send("PRIVMSG %s : Shutting down... \n" %(CHANNEL))
                    sys.exit(0)
                else:
                    pass
      
# get args

parser = argparse.ArgumentParser()
parser.add_argument('-m','--mq_host',default='localhost', help='Mqtt host to connect to')
parser.add_argument('-p','--mq_port',default='1883', help='Mqtt port to connect to')
parser.add_argument('-u','--mq_user',default='user', help='Mqtt user to auth with')
parser.add_argument('-P','--mq_pass',default='passwd', help='Mqtt password to authenticate with')
parser.add_argument('-s','--mq_subtop',default='stdin', help='Mqtt topic to subscribe to')
parser.add_argument('-t','--mq_pubtop',default='stdout', help='Mqtt topic to publish to')
parser.add_argument('-i','--irc_host',default='localhost', help='Irc host to connect to')
parser.add_argument('-I','--irc_port',default='6667', help='Irc port to connect to')
parser.add_argument('-n','--irc_nick',default='mqirc', help='Nick of irc user')
parser.add_argument('-c','--irc_chan',default='#mqtt', help='Irc channel to join')
parser.add_argument('-U','--priv_user',default='user', help='Irc bot owner')
parser.add_argument('-d','--debug', nargs='?', default=False, help='Print debug messages')
parser.add_argument('-v','--verbose', nargs='?', default=False, help='Verbose mode')
parser.add_argument('-b','--base64_on', nargs='?', default=False, help='Base64')




ns = parser.parse_args()

mq_host = ns.mq_host if ns.mq_host is not None else "default_mq_host"
mq_port = ns.mq_port if ns.mq_port is not None else "default_mq_port"
mq_user = ns.mq_user if ns.mq_user is not None else "default_mq_user"
mq_pass = ns.mq_pass if ns.mq_pass is not None else "default_mq_pass"
mq_subtop = ns.mq_subtop if ns.mq_subtop is not None else "default_mq_subtop"
mq_pubtop = ns.mq_pubtop if ns.mq_pubtop is not None else "default_mq_pubtop"
irc_host = ns.irc_host if ns.irc_host is not None else "default_irc_host"
irc_port = ns.irc_port if ns.irc_port is not None else "default_irc_port"
irc_nick = ns.irc_nick if ns.irc_nick is not None else "default_irc_nick"
irc_chan = ns.irc_chan if ns.irc_chan is not None else "default_irc_chan"
priv_user = ns.priv_user if ns.priv_user is not None else "default_priv_user"
debug = ns.debug if ns.debug is not None else "default_debug"
verbose = ns.verbose if ns.verbose is not None else "default_verbose"
base64_on = ns.base64_on if ns.base64_on is not None else "default_base64_on"

HOST = irc_host
PORT = int(irc_port)
NICK = irc_nick
CHANNEL = irc_chan



if base64_on:
    base64_on = True
    print("Base64 ON")
else:
    print("Base64 OFF")
if debug:
    debug = True
    print("Warning: Debug mode is ON")
    print("DEBUG: IRC Info: %s@%s:%s:%s, owner nick: %s" %(NICK, HOST, PORT, CHANNEL, priv_user))
    print("DEBUG: MQTT Info: %s@%s:%s, subscribe to: %s, publish to: %s " % (mq_user, mq_host, mq_port, mq_subtop, mq_pubtop))
else:
    print("Debug mode is OFF")
    
if verbose:
    verbose = True
    print("Verbose mode is ON")
    print("Connecting to ircd...")
# start'er up!!!
try:
    s=socket.socket( )
    s.connect((HOST, PORT))
    connect_irc()
    listen_irc()
except KeyboardInterrupt:
    print("Caught signal, shutting down...")
    sys.exit(0)
