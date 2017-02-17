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
bot_version = "1.5 Beta"
# initialize some vars
CHANNEL="";CHANNEL_="";NICK="";HOST=""
PORT='';pong_once='';priv_user="";data = ''
client="";userdata="";msg=""
# irc user stuff
IDENT="mqirc"
REALNAME="mqirc"
sent_m=False
dispass=""

######## Message parsing 
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
        
def isAscii(s):
    return all(ord(c) < 128 for c in s)

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

######## IRC Functions
def ircsend(action,target,message):
    if target==null:
        target=""
    if message==null:
        message=""
    if action==null:
        action="raw"
    if debug:
        print("Sending %s to %s" % (action,target))
    if action in ["PRIVMSG", "NOTICE"]:
        s.send("%s %s :%s\r\n" % (action,target,message))
    elif action in ["JOIN", "PONG", "NICK"]:
        s.send("%s %s\r\n" % (action,target))
    elif action in ["PART", "QUIT", "MODE", "USER"]:
        s.send("%s %s %s\r\n" % (action,target,message))
    elif action in "raw":
        s.send("%s\r\n" % message)
    else:
        if verbose or debug:
            print("Received unknown irc command")
            
def identify(irc_auth_):
    if irc_auth_ != "empty":
        if verbose: print("Identifying to nickserv with key: %s..." % irc_auth_)
        ircsend("PRIVMSG","nickserv","IDENTIFY %s" % irc_auth_)
    else:
        ircsend("PRIVMSG",CHANNEL,"Could not identify with nickserv")

def join_chan(join_str_):
    if verbose or debug: print("Joining %s" % join_str_)
    ircsend("JOIN",join_str_,null)

def mode(user, flags):
    if verbose or debug: print("Mode %s:%s" % (user,flags))
    ircsend( 'MODE ', user + " ",flags)

def op(to_op, chan):
    if verbose or debug: print("Opping %s" % to_op)
    ircsend( 'MODE ', chan, '+v: '+to_op)

def deop(to_deop, chan):
    if verbose or debug: print("Deopping %s" % to_deop)
    ircsend( 'MODE ', chan, '+v: '+to_op)

def voice(to_v, chan):
    if verbose or debug: print("Voicing %s" % to_v)
    ircsend( 'MODE ', chan, '+v: '+to_v)

def devoice(to_dv, chan):
    if verbose or debug: print("Devoicing %s" % to_dv)
    ircsend( 'MODE ', chan + ' -v: ' + to_dv)




# Called after first pong
def init_irc(CHANNEL_,KEY_,irc_auth_):
    if irc_auth_!="empty":
        identify(irc_auth_)
    time.sleep(1)
    mode(NICK,'+iwx')
    if debug or verbose:
        print("Joining (initial channel) %s" % CHANNEL_)
    if KEY_ != "lolololol":
        CHANNEL_ = CHANNEL_ + " " + KEY_
    join_chan(CHANNEL_)
    voice(CHANNEL,NICK)
    
def connect_irc(_irc_auth,_key):
    if debug:
        print("Connecting to mqtt...")
   
    if verbose:
        print("Connecting to irc with nick %s ..." % NICK)
    ircsend("NICK",NICK,null)
    ircsend("USER",IDENT+" "+HOST+" "+"8 :"+REALNAME,null)
    time.sleep(2)
    if KEY != "lolololol":
        CHANNEL = CHANNEL + " " + KEY
    join_chan(irc_chan+" "+KEY)

def part_chan(CHANNEL_):
    if verbose:
        print("Leaving channel %s" % CHANNEL_)
    ircsend("PART",CHANNEL_,null)

def quit_irc(sender_):
    ircsend("PRIVMSG",sender_,"Shutting down...")
    ircsend("QUIT","Peace out!",null)
    sys.exit(0)

def register(final, sender_):
    print("Registering with nickserv...")
    ircsend("PRIVMSG","nickserv","REGISTER "+final)
    ircsend("PRIVMSG",sender_,"Registered with nickserv.")

def gethost(irchost):                          # Return Host
    host = host.split('@')[1]
    host = host.split(' ')[0]
    return irchost

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

def bot_auth(_final_,dispass):
    if debug:
        print("Testing auth")
    _final_ = _final_.strip(" ")
    if _final_==dispass:
        print("Authentication success.")
        return True
    else:
        print("Authentication failure!")
        return False

def bot_whitelist(sender_,action_):
    if debug:
        print("Testing whitelist")
    match=0
    for i in range(len(auth_users)):
        if auth_users[i]==sender_:
            match+=1
    if match >=1:
        if verbose:
            print("Authorized sender %s" % sender_)
        return True
    else:
        print("Unauthorized sender %s" % sender_)
        ircsend("PRIVMSG","Unauthorized sender. This incident has been logged.",null)
        return False
    
def append_auth_users(action_, sender_,user_):
    if verbose:
        print("Appending %s to list" % user_)
    for i in range(len(auth_users)):
        if auth_users[i]==user_:
            print("Sender %s is already authorized" % user_)
            return False
    print("Appending %s to list" % user_)
    auth_users.append(user_)
    if action_!="null" or sender_!="null":
        ircsend(action_,sender_,"Appended "+user_+" to authorized users")
    
def delete_auth_users(action_, sender_,user_):
    if verbose:
        print("Removing user %s " % user_)
    for i in range(len(auth_users)):
        if auth_users[i]==user_:
            print("Removing user %s " % user_)
            auth_users.remove(user_)
            ircsend(action_,sender_,"Removed "+user_+" from authorized users")
            break
    print("User %s is not an authorized user" % user_)
    return False

def ret_auth_users(sender_,action_):
    if verbose:
        print("Sending auth users list to %s:\n %s" % (sender_,auth_users))
    ircsend(action_,sender_,"Current whitelisted channels and users")
    ircsend(action_,sender_,auth_users)

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
        ircsend("PRIVMSG",CHANNEL,message)
    else:     
        try:
            decoded = urlsafe_b64decode(str(message))
        except Exception as e:
            if debug:
                print("Plaintext: %s" % message)
            if isAscii(message):
                ircsend("PRIVMSG",CHANNEL,message)
                return
        else:
            #decoded = message
            decoded = decoded.replace("\"bot version:", "\"bot version\":")
            if debug:
                print(decoded)
            try:
                parsed_json = json.loads(decoded)
            except Exception as e:
                if debug:
                    print("Error %s" % e)
                if decoded:
                    ircsend("PRIVMSG",CHANNEL,decoded)
            else:
                parsed_ip = (parsed_json['ip'])
                parsed_msg = (parsed_json['output'])
                if debug:
                    print("Parsed JSON: %s %s \n" %(parsed_ip, parsed_msg))
                ircsend("PRIVMSG",CHANNEL,parsed_ip+" "+parsed_msg)

def handle_message(a, b, c):
    global sent_m
    global tcount
    global rcount
    if not sent_m:
        tcount=0
        rcount=0
    tcount+=1
    rcount+=1
    if tcount % 50 == 0:
        print("Message received: %s" % rcount)
        tcount=0
    on_message(a,b,c)
    sent_m=True
    
######## MQTT Functions
def mqsend(message):
    # make the request, should give us back some JSON
    client = mqtt.Client()
    publish.single(mq_pubtop, payload=str(message), hostname=mq_host, port=mq_port,auth = {'username':mq_user, 'password':mq_pass})

def connect_mqtt():
    # subscribe to topic
    client = mqtt.Client()
    client.on_connect = on_connect
    client.connect(mq_host, mq_port, 60)
    client.username_pw_set(username=mq_user,password=mq_pass)
    client.on_message = handle_message
    client.loop_start()


def listen_irc(irc_auth,chan_key,dispass,priv_user,CHANNEL):
    # Listen for incoming data
    global scount
    readbuffer=""
    scount=0
    pong_once=0
    enabled = False
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
                final = final + str(res[i])                
                final = final[:-2]
                final = final.replace("'","")
                final = final + " "
            if debug:
                print("\n%s\n" % final)

            if(line[0]=="PING"):
                if debug:
                    print("Received PING, sending PONG")
                ircsend("PONG",line[1],null)
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
                    break
            
                try:
                    sender = getchannel(rawbuffer)
                except:
                    sender = getnick(rawbuffer)
                sender = sender.strip(" ")
                if debug:
                    print("Sender:%s:" % sender)
                    print("Owner:%s:" % priv_user)
                    print("Channel:%s:" % CHANNEL)
            
          
                # enable
                if re.match(r'^:@enable.*$', line[3]):
                    print("Received auth enable request from %s" % sender)
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if not enabled:
                        if bot_auth(final,dispass):
                            
                            ircsend(action,sender,"Sucess. System ready.")
                            enabled = True
                        else:
                            ircsend(action,sender,"Authentication failed.")
                    else:
                        ircsend(action,sender,"Already enabled.")
                        
                # disable
                elif re.match(r'^:@disable.*$', line[3]):
                    print("Received auth disable request...")
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if not enabled:
                        ircsend(action,sender,"Already disabled.")
                    else:
                        if bot_auth(final,dispass):
                            ircsend(action,sender,"Success. System locked.")
                            enabled = False
                # publish mqtt message
                elif re.match(r'^:@cmd.*$', line[3]):
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    scount+=1
                    # fix for 'single quote' parsing
                    mrecv=rawbuffer.split(" :@cmd ")
                    final=mrecv[1]
                    final=final.strip("\r\n")
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
                        ircsend("PRIVMSG",sender,"Error publishing message")
                        if verbose:
                            print("Failed to publish message!")
                        if debug:
                            print("Error:\n %s" % e)
                # register with nickserv
                elif re.match(r'^:@register.*$', line[3]):
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if verbose:
                        print("Registering with nickserv...")
                    mrecv=rawbuffer.split(" :@register ")
                    final=mrecv[1]
                    final=final.strip("\r\n")
                    register(final, sender)
                    if debug:
                        print("Registered with nickserv: %s" % final)
                # raw irc command
                elif re.match(r'^:@irc.*$', line[3]):
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if verbose:
                        print("Sending raw irc command")
                    mrecv=rawbuffer.split(" :@irc ")
                    final=mrecv[1]
                    final=final.strip("\r\n")
                    if debug:
                        print("Received raw irc command:\n%s\n" % final)
                    #s.send("%s \r\n" % final)

                    ircsend(null,null,final)
                # echo something
                elif re.match(r'^:@echo.*$', line[3]):
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    mrecv=rawbuffer.split(" :@echo ")
                    final=mrecv[1]
                    final=final.strip("\r\n")
                    if debug:
                        print("Received PRIVMSG command:'%s'" % final)
                    ircsend(action,sender,final)
                # join channel
                elif re.match(r'^:@join.*$', line[3]):
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if verbose:
                        print("Received a join command")
                    join_chan(final)
                # part channel
                elif re.match(r'^:@part.*$', line[3]):
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if verbose:
                        print("Received a part command")
                    part_chan(final)
                # send usage
                elif re.match(r'^:@help.*$', line[3]):
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if verbose:
                        print("Sending usage\n")
                    bot_usage(action, sender)
                # list users
                elif re.match(r'^:@userlist.*$',line[3]):
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if verbose:
                        print("Sending user list to %s" % sender)
                    ret_auth_users(sender,action)
                # authorize user
                elif re.match(r'^:@adduser.*$',line[3]):
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    mrecv=rawbuffer.split(" :@adduser ")
                    final=mrecv[1]
                    final=final.strip("\r\n")
                    if verbose:
                        print("Request to authorized %s from %s" % (final,sender))
                    append_auth_users(action,sender,final)
                # unauth user
                elif re.match(r'^:@deluser.*$',line[3]):
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    mrecv=rawbuffer.split(" :@deluser ")
                    final=mrecv[1]
                    final=final.strip("\r\n")
                    if verbose:
                        print("Request to remove %s from %s" % (final,sender))
                    delete_auth_users(action,sender,final)
                # shut down
                elif re.match(r'^:@die.*$', line[3]):
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if verbose:
                        print("Shutting down...")
                    quit_irc(sender)
                
                else:
                    pass

def bot_usage(action, sender):
    if debug:
        print("Sending as : %s " % action)
    ircsend(action,sender,"======== MQIRC Version "+bot_version+" Bot Commands ========")
    ircsend(action,sender,"Bot responds to the following commands")
    ircsend(action,sender,"@cmd <message> : Send a message to pubtopic")
    ircsend(action,sender,"@help : Show this help")
    ircsend(action,sender,"@die : Shut down bot")
    ircsend(action,sender,"@echo <string> : Echo a message")
    ircsend(action,sender,"======= Authentication Commands ========:")
    ircsend(action,sender,"@enable <password> : Authenticate to and enable the boT")
    ircsend(action,sender,"@disable <password> : Lock bot. When disabled will only respond to @help")
    ircsend(action,sender,"@userlist : Send list of authorized senders")
    ircsend(action,sender,"@adduser <user/#channel> : Append nick/channel to authorized senders")
    ircsend(action,sender,"@deluser <user/#channel> : Remove nick/channel from authorized senders")
    ircsend(action,sender,"======== IRC Commands ========:")
    ircsend(action,sender,"@irc : <command> : Send a raw irc command to server")
    ircsend(action,sender,"@register <password> <email> : Register bot with nickserv")
    ircsend(action,sender,"@join : <channel> : Join this channel")
    ircsend(action,sender,"@part : <channel> : Leave this channel")
    ircsend(action,sender,"======== ========= ========")
   

######## Program start

from config import Config, ConfigList
from optparse import OptionParser

def getMergedConfig(filename):
    optcfg = Config()
    filecfg = Config(filename)
    parser = OptionParser()
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='Produce verbose output')
    parser.add_option('-d','--debug', action='store_true', dest='debug', help='Print debug messages')
    parser.add_option('-V','--very_verbose', action='store_true', dest='very_verbose', help='Very Verbose mode: Print all raw output')
    parser.add_option('-b','--base64_on', action='store_true', dest='base64_on', help='Base64')
    parser.add_option('-N','--notice', action='store_true', dest='notice', help='Respond to notices')

    parser.add_option('-m','--mq_host',default='localhost', help='Mqtt host to connect to')
    parser.add_option('-p','--mq_port',default='1883', help='Mqtt port to connect to')
    parser.add_option('-u','--mq_user',default='user', help='Mqtt user to auth with')
    parser.add_option('-P','--mq_pass',default='password', help='Mqtt password to authenticate with')
    parser.add_option('-s','--mq_subtop',default='data', help='Mqtt topic to subscribe to') 
    parser.add_option('-t','--mq_pubtop',default='shell', help='Mqtt topic to publish to')
    
    parser.add_option('-i','--irc_host',default='localhost', help='Irc host to connect to')
    parser.add_option('-I','--irc_port',default='6667', help='Irc port to connect to')
    parser.add_option('-n','--irc_nick',default='mqirc', help='Nick of irc user')
    parser.add_option('-c','--irc_chan',default='#mqtt', help='Irc channel to join')
    parser.add_option('-k','--chan_key',default='lolololol', help='Channel key')
    parser.add_option('-a','--irc_auth',default='empty', help='Password to auth with nickserv')
    parser.add_option('-K','--bot_key',default='mqirc', help='Password to auth with bot')
    parser.add_option('-U','--priv_user',default='anon', help='Irc bot owner')
    args = parser.parse_args(None, optcfg)[1]
    cfglist = ConfigList()
    cfglist.append(optcfg)
    cfglist.append(filecfg)
    return cfglist, args

auth_users = ['anon', '#mqtt']

cfg, args = getMergedConfig('mqconfig.cfg')

verbose=cfg.getByPath('verbose')
very_verbose=cfg.getByPath('very_verbose')
notice=cfg.getByPath('notice')    
base64_on=cfg.getByPath('base64_on')
debug=cfg.getByPath('debug')

mq_host=cfg.getByPath('mq_host')
mq_port=cfg.getByPath('mq_port')
mq_user=cfg.getByPath('mq_user')
mq_pass=cfg.getByPath('mq_pass')
mq_subtop=cfg.getByPath('mq_subtop')
mq_pubtop=cfg.getByPath('mq_pubtop')

irc_auth=cfg.getByPath('irc_auth')
irc_nick=cfg.getByPath('irc_nick')
irc_host=cfg.getByPath('irc_host')
irc_port=cfg.getByPath('irc_port')
irc_chan=cfg.getByPath('irc_chan')
chan_key=cfg.getByPath('chan_key')
bot_key=cfg.getByPath('bot_key')
priv_user=cfg.getByPath('priv_user')

HOST = irc_host
PORT = int(irc_port)
NICK = irc_nick
CHANNEL = irc_chan
KEY = chan_key
dispass = str(bot_key)
null="null"
append_auth_users(null,null,priv_user)
append_auth_users(null,null,CHANNEL)

if verbose:
    print("Default Bot password: 'mqirc'")

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
    try:
        s.connect((HOST, PORT))
    except Exception as x:
        print(x)
    else:
        print("Connected to irc server...")
    connect_irc(irc_auth,KEY)
    connect_mqtt()
    listen_irc(irc_auth,KEY,dispass,priv_user,CHANNEL)
except KeyboardInterrupt:
    print("Caught signal, shutting down...")
    sys.exit(0)
