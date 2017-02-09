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

#### BASIC INFORMATION ABOUT THE MQTT CONNECTION ##############################
global mq_host
global mq_port
global sub_topic
global pub_topic
global mq_user
global mq_pass
#### BASIC INFORMATION ABOUT THE IRC CONNECTION ##############################
global irc_host
global irc_port
global irc_nick
global irc_chan

CHANNEL=""
NICK=""
IDENT="mqirc"
REALNAME="mqirc"
HOST=""
PORT=''

data = ''

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
    """Breaks a message from an IRC server into its prefix, command, and arguments.
    """
    prefix = ''
    trailing = []
    if not s:
       raise IRCBadMessage("Empty line.")
    if s[0] == ':':
        prefix, s = s[1:].split(' ', 1)
    if s.find(' :') != -1:
        s, trailing = s.split(' :', 1)
        args = s.split()
        args.append(trailing)
    else:
        args = s.split()
    command = args.pop(0)
    return args

def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))
    client.subscribe(mq_subtop)

def on_message(client, userdata, msg):
    message = str(msg.payload)
    try:
        decoded = urlsafe_b64decode(str(message))
    except Exception as e:
        if message:
            print("Plaintext: %s" % message)
            s.send("PRIVMSG %s :%s \n" %(CHANNEL, message))
    else:
        #print(decoded)
        decoded = decoded.replace("\"bot version:", "\"bot version\":") # hack cause my json was invalid
        print(decoded)
        try:
            parsed_json = json.loads(decoded)
        except Exception as e:
            #pass
            print("Error %s" % e)
            #print(decoded)
            if decoded:
                s.send("PRIVMSG %s :%s \n" %(CHANNEL, decoded))
        else:
            parsed_ip = (parsed_json['ip'])
            parsed_msg = (parsed_json['output'])
            #, 'status', 'cmdline', 'output'
            #print(parsed_msg)
            print("Parsed JSON: %s %s \n" %(parsed_ip, parsed_msg))
            s.send("PRIVMSG %s :%s %s \n" %(CHANNEL, parsed_ip, parsed_msg))

def connect_mqtt():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.connect(mq_host, mq_port, 60)
    client.username_pw_set(username=mq_user,password=mq_pass)
    client.on_message = on_message
    client.loop_start()

def mqsend(message):
    # make the request, should give us back some JSON
    client = mqtt.Client()
    publish.single(mq_pubtop, payload=str(message), hostname=mq_host, port=mq_port,auth = {'username':mq_user, 'password':mq_pass})


#### OPEN A CONNECTION ###################################################



def connect_irc():
    connect_mqtt()
#### SESSION MUST START LIKE THIS ########################################
    s.send("NICK %s\r\n" % NICK)
    s.send("USER %s %s bla :%s\r\n" % (IDENT, HOST, REALNAME))
    time.sleep(2)
    #s.send("MODE %s +xiw\r\n" % NICK)
    s.send("JOIN %s\r\n" % CHANNEL)
#### Listen for incoming data
def listen_irc():
    readbuffer=""
    while 1:
        readbuffer=readbuffer+s.recv(100000)  # O'Reilly's size is too small
        temp=string.split(readbuffer, "\n")  # for some welcome pages
        #print (readbuffer)                   # Print raw output to screen        
        readbuffer=temp.pop( )
        for line in temp:
            line=string.rstrip(line)
            line=string.split(line)
            if(line[0]=="PING"):
                s.send("PONG %s\r\n" % line[1])
            elif line[1]=="PRIVMSG":
                if re.match('^[@cmd\w].*$', line[-1]):
                    print("Parsing and sending message")
                    res = parse_message(str(line))
                    final = ''
                    for i in range(3, len(res)):
                        final = final + str(res[i])
                        final = final.replace("'", "")
                        final = final.replace(",", " ")
                    final = final[:-1]
                    print(final)
                    final = b64encode(final)
                    #print(final)
                    try:
                        mqsend(final)
                    except:
                        print("Some error!")
                else:
                    pass


parser = argparse.ArgumentParser()
parser.add_argument('-m','--mq_host',default='localhost', help='Mqtt host to connect to')
parser.add_argument('-p','--mq_port',default='1883', help='Mqtt port to connect to')
parser.add_argument('-u','--mq_user',default='user', help='Mqtt user to auth with')
parser.add_argument('-P','--mq_pass',default='passwd', help='Mqtt password to authenticate with')
parser.add_argument('-s','--mq_subtop',default='in/#', help='Mqtt topic to subscribe to')
parser.add_argument('-t','--mq_pubtop',default='out/#', help='Mqtt topic to publish to')
parser.add_argument('-i','--irc_host',default='localhost', help='Irc host to connect to')
parser.add_argument('-I','--irc_port',default='6667', help='Irc port to connect to')
parser.add_argument('-n','--irc_nick',default='mqirc', help='Nick of irc user')
parser.add_argument('-c','--irc_chan',default='#mqirc', help='Irc channel to join')



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


HOST = irc_host
PORT = int(irc_port)
NICK = irc_nick
CHANNEL = irc_chan

s=socket.socket( )
s.connect((HOST, PORT))

connect_irc()
listen_irc()

