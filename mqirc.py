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
import shlex,subprocess
import logging
#import netaddr,hashlib
from ircolors import Colours as iC
from config import Config, ConfigList
from optparse import OptionParser

logger = logging.getLogger(__name__)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# version of this bot
bot_version = "2.2 Beta"
# initialize some vars
CHANNEL="";CHANNEL_="";NICK="";HOST=""
PORT='';pong_once='';priv_user="";data = ''
client="";userdata="";msg=""
# irc user stuff
IDENT="mqirc"
REALNAME="mqirc"
sent_m=False
dispass=""
simple_out=False
######## Message parsing

def ic(color,string):
    """ Wrapper function for class ircolors """
    return iC(color, string).get()

def b64encode(s, altchars=None):
    """ function for base64 encoding """
    encoded = binascii.b2a_base64(s)[:-1]
    if altchars is not None:
        return _translate(encoded, {'+': altchars[0], '/': altchars[1]})
    return encoded

def urlsafe_b64decode(s):
    
    """ function for base64 decoding """
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
    """ function to test if a string is valid ascii"""
    return all(ord(c) < 128 for c in s)

def parse_message(s):
    """ Breaks a message from an IRC server into its prefix, command, and arguments. """
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
        logger.debug("Parsing message: \r\nPrefix: %s Args: %s Trailing: %s \n" %(prefix, args, trailing))
    return args

######## IRC Functions
def ircsend(action,target,message):
    """ messy function for sending irc messages """
    if target==null: target=""
    if message==null: message=""
    if action==null: action="raw"
    if debug: print("Sending %s to %s" % (action,target))
    logger.debug("Sending %s to %s" % (action,target))
    if action in ["PRIVMSG", "NOTICE"]:
        if type(message)==list:
            s.send("%s %s :%s\r\n" % (action,target,message))
        else:
            ret=message.strip("\r")
            ret = ret.split("\n")
            for line in ret:
                line=line.strip("\n")
                if line!=" ":
                    s.send("%s %s :%s\r\n" % (action,target,line))
        #s.send("%s %s :%s\r\n" % (action,target,message))
    elif action in ["JOIN", "PONG", "NICK"]:
        s.send("%s %s\r\n" % (action,target))
    elif action in ["PART", "QUIT", "MODE", "MODE ", "USER"]:
        s.send("%s %s %s\r\n" % (action,target,message))
    elif action in "raw":
        s.send("%s\r\n" % message)
    else:
        if verbose or debug:
            print("Received unknown irc command")
        logger.info("Received unknown irc command : %s" % action )
            
def identify(irc_auth_):
    """ identify bot with nickserv """
    if irc_auth_ != "empty":
        logger.debug("Identifying to nickserv with key: %s..." % irc_auth_)
        if verbose: print("Identifying to nickserv with key: %s..." % irc_auth_)
        ircsend("PRIVMSG","nickserv","IDENTIFY %s" % irc_auth_)
    else:
        ircsend("PRIVMSG",CHANNEL,"Could not identify with nickserv")

def join_chan(join_str_):
    """ joins a channel """
    logger.info("Joining %s" % join_str_)
    if verbose or debug: print("Joining %s" % join_str_)
    ircsend("JOIN",join_str_,null)

def mode(user, flags):
    """ generic user mode function """
    logger.info("Mode %s:%s" % (user,flags))
    if verbose or debug: print("Mode %s:%s" % (user,flags))
    ircsend( 'MODE ', user + " ",flags)


def op(to_op, chan):
    """ not yet implemented, for future uses """
    logger.info("Opping %s" % to_op)
    if verbose or debug: print("Opping %s" % to_op)
    ircsend( 'MODE ', chan, '+v: '+to_op)

def deop(to_deop, chan):
    logger.info("Deopping %s" % to_deop)
    if verbose or debug: print("Deopping %s" % to_deop)
    ircsend( 'MODE ', chan, '+v: '+to_op)

def voice(to_v, chan):
    """ irc mode +v """
    logger.info("Voicing %s" % to_v)
    if verbose or debug: print("Voicing %s" % to_v)
    ircsend( 'MODE ', chan, '+v: '+to_v)

def devoice(to_dv, chan):
    logger.info("Devoicing %s" % to_dv)
    if verbose or debug: print("Devoicing %s" % to_dv)
    ircsend( 'MODE ', chan + ' -v: ' + to_dv)




# Called after first pong because some server are weird about that
def init_irc(CHANNEL_,KEY_,irc_auth_):
    if irc_auth_!="empty":
        identify(irc_auth_)
    time.sleep(1)
    mode(NICK,'+iwx')
    logger.info("Init IRC, Joining %s" % CHANNEL_)
    if debug or verbose:
        print("Joining (initial channel) %s" % CHANNEL_)
    if KEY_ != "lolololol":
        CHANNEL_ = CHANNEL_ + " " + KEY_
    join_chan(CHANNEL_)
    logger.info("Setting mode +v")
    voice(CHANNEL,NICK)
    
def connect_irc(_irc_auth,_key):
    """ This is where we join the home channel  """
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
    logger.info("Leaving channel %s" % CHANNEL_)
    if verbose:
        print("Leaving channel %s" % CHANNEL_)
    ircsend("PART",CHANNEL_,null)

def quit_irc(sender_):
    """ Properly shut down the bot """
    logger.info("Shutting down with dignity...")
    ircsend("PRIVMSG",sender_,"Shutting down...")
    ircsend("QUIT","Peace out!",null)
    sys.exit(0)

def register(final, sender_):
    """ Register bot with nickserv """
    logger.info("Registering with nickserv...")
    print("Registering with nickserv...")
    ircsend("PRIVMSG","nickserv","REGISTER "+final)
    ircsend("PRIVMSG",sender_,"Registered with nickserv.")

""" Functions for parsing nick, host, user, and ident stuff """
def getuser(data):
    botmsg = data.split(':')[1]
    user_ = botmsg.split(' ')[0]
    return user_

def gethost(data):
    botmsg = data.split(':')[1]
    user_ = botmsg.split(' ')[0]
    host_ = user_.split('@')[1]
    return host_

    return host_
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
    """ Check disable/enable pass (dispass) """
    if debug:
        print("Testing auth")
    _final_ = _final_.strip(" ")
    if _final_==dispass:
        print("Authentication success.")
        logger.info("Bot has been enabled, awating orders...")
        return True
    else:
        print("Authentication failure!")
        logger.info("Failed authentication!")
        return False

def bot_whitelist(sender_,action_):
    """ Check that the sender channel or nick is authorized """
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
        logger.info("Unauthorized message from sender %s" % sender_)
        print("Unauthorized sender %s" % sender_)
        ircsend("PRIVMSG","Unauthorized sender. This incident has been logged.",null)
        return False
    
def append_auth_users(action_, sender_,user_):
    """ Add an authorized user or channel """
    if verbose:
        print("Appending %s to list" % user_)
    for i in range(len(auth_users)):
        if auth_users[i]==user_:
            print("Sender %s is already authorized" % user_)
            return False
    print("Appending %s to list" % user_)
    logger.info("Appending %s to list" % user_)
    auth_users.append(user_)
    if action_!="null" or sender_!="null":
        ircsend(action_,sender_,"Appended "+user_+" to authorized users")
    
def delete_auth_users(action_, sender_,user_):
    """ Remove an authorized user or channel """
    if verbose:
        print("Removing user %s " % user_)
    for i in range(len(auth_users)):
        if auth_users[i]==user_:
            print("Removing user %s " % user_)
            auth_users.remove(user_)
            logger.info("Removing user %s " % user_)
            ircsend(action_,sender_,"Removed "+user_+" from authorized users")
            break
    print("User %s is not an authorized user" % user_)
    return False

def ret_auth_users(sender_,action_):
    """ Return a list of authorized users """
    if verbose:
        print("Sending auth users list to %s:\n %s" % (sender_,auth_users))
    logger.info("List user request: %s" % sender_)
    ircsend(action_,sender_,"Current whitelisted channels and users")
    ircsend(action_,sender_,auth_users)

def on_connect(client, userdata, flags, rc):
    """ Generic mqtt connect function """
    print("Connected with result code "+str(rc))
    logger.info("Mqtt connection succeeded with result code %s" % str(rc))
    client.subscribe(mq_subtop)


def on_message(client, userdata, msg):
    """ When an MQTT message is received, parse and send it to the home channel  """
    message = str(msg.payload)
    if debug:
        logger.debug("Received mqtt message")
        print("Received message")
    if not base64_on:
        if debug:
            print("Not attempting base64 decode since -b was not specified")
        ircsend("PRIVMSG",CHANNEL,message)
    else:
        """ If base64_on is true, first test that the message is valid base64 """
        try:
            decoded = urlsafe_b64decode(str(message))
        except Exception as e:
            if debug:
                print("Plaintext: %s" % message)
            """ If the message is not base64, but is valid ascii,
            and not valid json, than its plaintext, so we send it """
            if isAscii(message) and not json.loads(message):
                ircsend("PRIVMSG",CHANNEL,message)
                return
        else:
            """ This is an example hack of what to do if your json is invalid
            try:
                decoded = decoded.replace("\"bot version:", "\"bot version\":")
            except:
                pass
            """
            if debug:
                print(decoded)
            """ load json into memory """    
            try:
                parsed_json = json.loads(decoded)
            except Exception as e:
                if debug:
                    print("Error %s" % e)
                """ if we made it this far and its still not json , just send it plaintext """
                if decoded:
                    ircsend("PRIVMSG",CHANNEL,decoded)
            else:
                """ if it is valid json, parse the desired fields 
                [* NOTE]: You need to customize which fields you want to display according to your uses. If you're not
                using json, than don't worry about it.
                """
                if not simple_out:
                    ip_=parsed_json['ip']
                    a=ip_.split(".")
                    ip=(str(a[0])+"."+str("xx")+"."+str(a[2])+str(".xx"))
                    data_=(ic("4","{\n")+ic("6","ip: ")+ic("3",ip)+"\n"+
                          ic("6","utx: ")+ic("3",parsed_json['unixtime']+"\n")+
                          ic("6","cpu: ")+ic("3",parsed_json['cpuname']+"\n")+
                          ic("6","memstat: ")+ic("3",parsed_json['memstat']+"\n")+
                          ic("6","id: ")+ic("3",parsed_json['id']+"\n")+
                          ic("6","uptime: ")+ic("3",parsed_json['uptime']+"\n")+
                          ic("6","version: ")+ic("3",parsed_json['version']+"\n")+
                          ic("6","kernel: ")+ic("3",parsed_json['kernel_cmdline']+"\n")+
                          ic("6","shlvl: ")+ic("3",parsed_json['shell level']+"\n")+
                          ic("6","crypto: ")+ic("3",parsed_json['kernel_crypto']+"\n")+
                          ic("6","default shell: ")+ic("3",parsed_json['default shell']+"\n")+
                          ic("6","current shell: ")+ic("3",parsed_json['current shell']+"\n")+
                          ic("6","term: ")+ic("3",parsed_json['term']+"\n")+
                          ic("6","stty: ")+ic("3",parsed_json['stty']+"\n")+
                          ic("6","cwd: ")+ic("3",parsed_json['cwd']+"\n")+
                          ic("6","uuid: ")+ic("3",parsed_json['uuid']+"\n")+
                          ic("6","status: ")+ic("3",parsed_json['status']+"\n")+
                          ic("6","bot version: ")+ic("3",parsed_json['bot version']+"\n")+
                          ic("6","cmdline: ")+ic("3",parsed_json['cmdline']+"\n")+
                          ic("2","output: ")+ic("7",parsed_json['output']+"\n")+ic("4","}"))

                else:
                  """ This is simplified or 'cleaner' (-C) output, 
                  [* NOTE]:you need to customize your own json fields
                  """
                    ip_=parsed_json['ip']
                    a=ip_.split(".")
                    ip=(str(a[0])+"."+str("xx")+"."+str(a[2])+str(".xx"))
                    data_=(ic("red",str("{ "))+ic("purple",str(ip)+" "+parsed_json['bot version']+": ")+ic("7",parsed_json['output'])+ic("red"," }"))
                           
    
                
                if debug:
                       print("Parsed JSON: %s \n" % data_)
                """ Finally, send the parsed json to the home channel """
                ircsend("PRIVMSG",CHANNEL,data_)
                

def handle_message(a, b, c):
    """ function to wrap on_message so we can count received mqtt messages """
    global sent_m
    global tcount
    global rcount
    if not sent_m:
        tcount=0
        rcount=0
    tcount+=1
    rcount+=1
    """ Every 50 messages send a privmsg to channel with message count """
    if tcount % 50 == 0:
        print("Message received: %s" % rcount)
        logger.info("Message received: %s" % rcount)
        tcount=0
        msg=ic("red",str("{ Messages Received: "+str(rcount)+str(" }")))
        ircsend("PRIVMSG",CHANNEL,msg)
    on_message(a,b,c)
    sent_m=True
    
######## MQTT Functions
def mqsend(message):
    """ Publishes a message to pubtop """
    client = mqtt.Client()
    publish.single(mq_pubtop, payload=str(message), hostname=mq_host, port=mq_port,auth = {'username':mq_user, 'password':mq_pass})

def connect_mqtt():
    """ initialize mqtt subscription(s) """
    client = mqtt.Client()
    client.on_connect = on_connect
    client.connect(mq_host, mq_port, 60)
    client.username_pw_set(username=mq_user,password=mq_pass)
    client.on_message = handle_message
    client.loop_start()

#########
def shell_cmd(cmd):
    """ provides a local shell, accessable over irc """
    command_line = cmd
    logger.warn("Executing a shell command: %s" % cmd)
    args = shlex.split(command_line)
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output=iter(p.stdout.readline, b'')
    ret=''
    for line in output:
        ret = ret + str(line) + " "
    return ret

    
def listen_irc(irc_auth,chan_key,dispass,priv_user,CHANNEL,shell_enabled):
    """ Listen for incoming IRC data and act accordingly """
    global scount
    readbuffer=""
    scount=0
    pong_once=0
    enabled = False
    s_channel=""
    s_user=""
    s_nick=""
    while True:        
        readbuffer=readbuffer+s.recv(1000000)  
        temp=string.split(readbuffer, "\n")
        rawbuffer=readbuffer
        """ try to parse some more detailed sender info for logging """
        try:
            s_nick=getnick(rawbuffer)
        except:
            pass
        try:
            s_user=getuser(rawbuffer)
        except:
            pass
        try:
            s_channel=getchannel(rawbuffer)
        except:
            pass
        if debug:
            print("Got a message. Nick: "+s_nick+" Host: "+s_user+" Channel: "+s_channel)
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
                logger.debug("Ping, pong!")
                if debug:
                    print("Received PING, sending PONG")
                ircsend("PONG",line[1],null)
                pong_once+=1
                if (pong_once == 1):
                    logger.info("Received first ping, will now initialize irc")
                    init_irc(CHANNEL,chan_key,irc_auth)
            elif (line[1]=="PRIVMSG" or line[1]=="NOTICE"):
                logger.debug("Contents of received message : %s" % line)
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

                """ Bot command logic  """
          
                # enable
                if re.match(r'^:@enable.*$', line[3]):
                    print("Received auth enable request from %s" % sender)
                    logger.info("Auth request from: nick: "+s_nick+" ident: "+s_user)
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        logger.info("Failed auth attempt from: %s" % sender)
                        break
                    if not enabled:
                        if bot_auth(final,dispass):
                            
                            ircsend(action,sender,"Sucess. System ready.")
                            logger.info("Auth success by: %s" % sender)
                            enabled = True
                        else:
                            ircsend(action,sender,"Authentication failed.")
                            logger.info("Auth failure by: %s" % sender)
                    else:
                        ircsend(action,sender,"Already enabled.")
                        
                # disable
                elif re.match(r'^:@disable.*$', line[3]):
                    print("Received auth disable request...")
                    logger.info("Received auth disable request from: nick: "+s_nick+" ident: "+s_user)
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if not enabled:
                        ircsend(action,sender,"Already disabled.")
                    else:
                        if bot_auth(final,dispass):
                            ircsend(action,sender,"Success. System locked.")
                            logger.info("System locked by: %s" % sender)
                            enabled = False
                # publish mqtt message
                elif re.match(r'^:@cmd.*$', line[3]):
                    logger.info("Received cmd req from: nick: "+s_nick+" ident: "+s_user)
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    scount+=1
                    mrecv=rawbuffer.split(" :@cmd ")
                    final=mrecv[1]
                    final=final.strip("\r\n")
                    logger.info("Published cmd : %s , sender: %s" % (final,sender))
                   
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
                    logger.info("Received register req from: nick: "+s_nick+" ident: "+s_user)
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if verbose:
                        print("Registering with nickserv...")
                    
                    mrecv=rawbuffer.split(" :@register ")
                    try:
                        final=mrecv[1]
                    except IndexError:
                        ircsend(action,sender,"Register <password> <email>")
                        pass
                    final=final.strip("\r\n")
                    register(final, sender)
                    if debug:
                        print("Registered with nickserv: %s" % final)
                # raw irc command
                elif re.match(r'^:@irc.*$', line[3]):
                    logger.info("Received raw irc req from: nick: "+s_nick+" ident: "+s_user)
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
                    logger.info("Raw irc command: %s , sender: %s" %(final, sender))
                    if debug:
                        print("Received raw irc command:\n%s\n" % final)
                    #s.send("%s \r\n" % final)

                    ircsend(null,null,final)
                # echo something
                elif re.match(r'^:@echo.*$', line[3]):
                    logger.info("Received cmd req echo from: nick: "+s_nick+" ident: "+s_user)
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    mrecv=rawbuffer.split(" :@echo ")
                    final=mrecv[1]
                    final=final.strip("\r\n")
                    logger.info("Echo command: %s , sender: %s" % (final,sender))
                    if debug:
                        print("Received PRIVMSG command:'%s'" % final)
                    ircsend(action,sender,final)
                # join channel
                elif re.match(r'^:@join.*$', line[3]):
                    logger.info("Received join req from: nick: "+s_nick+" ident: "+s_user)
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if verbose:
                        print("Received a join command")
                    logger.info("Joining %s, sender: %s" %(final,sender))
                    join_chan(final)
                # part channel
                elif re.match(r'^:@part.*$', line[3]):
                    logger.info("Received part req from: nick: "+s_nick+" ident: "+s_user)
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if verbose:
                        print("Received a part command")
                    logger.info("Parting %s, sender: %s" %(final,sender))
                    part_chan(final)
                # send usage
                elif re.match(r'^:@help.*$', line[3]):               
                    logger.info("Received help req from: nick: "+s_nick+" ident: "+s_user)
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if verbose:
                        print("Sending usage\n")
                    logger.info("Sending usage to sender: %s" % sender)
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
                    logger.info("Sending user list to sender: %s" % sender)
                    ret_auth_users(sender,action)
                # authorize user
                elif re.match(r'^:@adduser.*$',line[3]):
                    logger.info("Received adduser req from: nick: "+s_nick+" ident: "+s_user)
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
                    logger.info("Request to authorized %s from %s" % (final,sender))
                    append_auth_users(action,sender,final)
                # unauth user
                elif re.match(r'^:@deluser.*$',line[3]):
                    logger.info("Received deluser req from: nick: "+s_nick+" ident: "+s_user)
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    mrecv=rawbuffer.split(" :@deluser ")
                    final=mrecv[1]
                    final=final.strip("\r\n")
                    logger.info("Request to remove user: %s from sender: %s" % (final,sender))
                    if verbose:
                        print("Request to remove %s from %s" % (final,sender))
                    delete_auth_users(action,sender,final)
                # shut down
                elif re.match(r'^:@die.*$', line[3]):
                    logger.info("Received die req from: nick: "+s_nick+" ident: "+s_user)
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    
                    print("Shutting down...")
                    logger.info("Shutting down because: received die, from sender: %s" % sender)
                    time.sleep(1)
                    quit_irc(sender)
                elif re.match(r'^:@shell.*$', line[3]):
                    logger.info("Received shell req from: nick: "+s_nick+" ident: "+s_user)
                    if not enabled:
                        ircsend(action,sender,"Access denied.")
                        break
                    if not bot_whitelist(sender, action):
                        ircsend(action,sender,"Access denied.")
                        break
                    if not shell_enabled:
                        ircsend(action,sender,"Shell is disabled. This incident has been logged.")
                        logger.info("Failed attempted shell command from: %s " % sender)
                        logger.info("Unauthorized command was: %s" % final)
                        break
                    if verbose:
                        print("Received shell command: %s from sender: %s" % (final,sender))
                    mrecv=rawbuffer.split(" :@shell ")
                    final=mrecv[1]
                    final=final.strip("\r")
                    logger.info("Executing %s, sender: %s" %(final,sender))
                    ret = shell_cmd(final)
                    ret = ret.split("\n")
                    
                    for line in ret:
                        line=line.strip("\n")
                        if line!=" ":
                            ircsend(action,sender,line)
                            logger.info("Output of shell command %s" % (line))
                        
                
                else:
                    pass

def bot_usage(action, sender):
    if debug:
        print("Sending as : %s " % action)
    ircsend(action,sender,ic("red",str("======== MQIRC Version ")+bot_version+str("Bot Commands ========")))
    ircsend(action,sender,ic("11",str("Bot responds to the following commands")))
    ircsend(action,sender,ic("11",str("@cmd :"+ic("6","<message> Send a message to pubtopic"))))
    ircsend(action,sender,ic("11",str("@help :" +ic("6","  Show this help"))))
    ircsend(action,sender,ic("11",str("@die : "+ic("6"," Shut down bot"))))
    ircsend(action,sender,ic("11",str("@echo :"+ic("6"," <string>  Echo a message"))))
    ircsend(action,sender,ic("11",str("@shell :"+ic("6"," <command>  Execute shell a command locally"))))
    ircsend(action,sender,ic("red",str("======= Authentication Commands ========")))
    ircsend(action,sender,ic("11",str("@enable : "+ic("6", "<password> : Authenticate to and enable the boT"))))
    ircsend(action,sender,ic("11",str("@disable : "+ic("6", "<password> : Lock bot. When disabled will only respond to @help"))))
    ircsend(action,sender,ic("11",str("@userlist :"+ic("6","Send list of authorized senders"))))
    ircsend(action,sender,ic("11",str("@adduser : "+ic("6", "<user/#channel> : Append nick/channel to authorized senders"))))
    ircsend(action,sender,ic("11",str("@deluser : " +ic("6", "<user/#channel> : Remove nick/channel from authorized senders"))))
    ircsend(action,sender,ic("red",str("======== IRC Commands ========")))
    ircsend(action,sender,ic("11",str("@irc :"+ic("6","<command> : Send a raw irc command to server"))))
    ircsend(action,sender,ic("11",str("@register :"+ic("6","<password> <email> Register bot with nickserv"))))
    ircsend(action,sender,ic("11",str("@join :"+ic("6","<channel> Join this channel"))))
    ircsend(action,sender,ic("11",str("@part :"+ic("6","<channel> Leave this channel"))))
    ircsend(action,sender,ic("red",str("======== ========= ========")))
   
   


def getMergedConfig(filename):
    optcfg = Config()
    filecfg = Config(filename)
    parser = OptionParser()
    parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='Produce verbose output')
    parser.add_option('-d','--debug', action='store_true', dest='debug', help='Print debug messages')
    parser.add_option('-V','--very_verbose', action='store_true', dest='very_verbose', help='Very Verbose mode: Print all raw output')
    parser.add_option('-S','--shell_enabled', action='store_true', dest='shell_enabled', help='Enable system shell (potentially dangerous!)')
    parser.add_option('-b','--base64_on', action='store_true', dest='base64_on', help='Base64')
    parser.add_option('-N','--notice', action='store_true', dest='notice', help='Respond to notices')
    parser.add_option('-C','--cleaner', action='store_true', dest='cleaner', help='Simplify output of mqtt json')                             

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
######## Program start

auth_users = ['anon', 'kek', '#mqtt']

cfg, args = getMergedConfig('mqconfig.cfg')

verbose=cfg.getByPath('verbose')
very_verbose=cfg.getByPath('very_verbose')
shell_enabled=cfg.getByPath('shell_enabled')
notice=cfg.getByPath('notice')    
base64_on=cfg.getByPath('base64_on')
debug=cfg.getByPath('debug')
cleaner=cfg.getByPath('cleaner')

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


# create a file handler
handler = logging.FileHandler('mqirc.log')
handler.setLevel(logging.INFO)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)

if verbose:
    print("Default Bot password: 'mqirc'")

if notice:
    notice=True
    print("Respond to notice: ON")
    logger.info('Respond to notice is on.')
else:
    print("Respond to notice: OFF")


if base64_on:
    base64_on = True
    print("Base64 ON")
    logger.info('Base64 encoding is on.')
else:
    print("Base64 OFF")
if debug:
    debug = True
    print("Warning: Debug mode is ON")
    logger.info('Debug mode is on.')
else:
    print("Debug mode is OFF")

if very_verbose:
    very_verbose = True
    print("Very Verbose mode is ON")
    
if verbose:
    verbose = True
    print("Verbose mode is ON")
    logger.info('Verbose mode is ON')
    print("IRC Info: %s@%s:%s:%s, owner nick: %s" %(NICK, HOST, PORT, CHANNEL, priv_user))
    logger.info("IRC Info: %s@%s:%s:%s, owner nick: %s" %(NICK, HOST, PORT, CHANNEL, priv_user))
    print("MQTT Info: %s@%s:%s, subscribe to: %s, publish to: %s " % (mq_user, mq_host, mq_port, mq_subtop, mq_pubtop))
    logger.info("MQTT Info: %s@%s:%s, subscribe to: %s, publish to: %s " % (mq_user, mq_host, mq_port, mq_subtop, mq_pubtop))
    print("Connecting to ircd...")

if cleaner:
    logger.info("Simple out is ON")
    print("Simple out is ON")
    simple_out=True

try:
    s=socket.socket( )
    try:
        s.connect((HOST, PORT))
    except Exception as x:
        print(x)
    else:
        print("Connected to irc server...")
        logger.info("Connection to irc succeeded")
    connect_irc(irc_auth,KEY)
    connect_mqtt()
    listen_irc(irc_auth,KEY,dispass,priv_user,CHANNEL,shell_enabled)
except KeyboardInterrupt:
    print("Caught signal, shutting down...")
    logger.info("Shutting down because caught signal...")
    sys.exit(0)
