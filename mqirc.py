#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
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
"""
import sys
import socket
import string,time,re
import paho.mqtt.client as mqtt
import paho.mqtt.publish as publish
import binascii
import base64
import operator
import json
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
    client.subscribe("data/out")

def on_message(client, userdata, msg):
    message = str(msg.payload)
    try:
        decoded = urlsafe_b64decode(str(message))
    except Exception as e:
        #pass # to relay messages that did not arrive as valid base64...
        print(message)
        s.send("PRIVMSG %s :%s \n" %(CHANNEL, message))
    else:
        #print(decoded)
        #decoded = decoded.replace("\"'", r'"')
        #decoded = decoded.replace("'\",", r'",')
        print(decoded)
        try:
            parsed_json = json.loads(decoded)
        except Exception as e:
            print("Error %s" % e)
        else:
            parsed_msg = (parsed_json['output'])
            #print(parsed_msg)
            s.send("PRIVMSG %s :%s \n" %(CHANNEL, parsed_msg))

def connect_mqtt():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.connect("127.0.0.1", 1883, 60)
    client.on_message = on_message
    client.loop_start()
    #client.start()
def mqsend(message):
    # make the request, should give us back some JSON
    client = mqtt.Client()
    publish.single("shell/in", payload=str(message), hostname="localhost")
    



#### BASIC INFORMATION ABOUT THE IRC CONNECTION ##############################
HOST="localhost"
PORT=6667
NICK="ircmq"
IDENT="lol"
REALNAME="shellz"
CHANNEL="#mqtt"
#### OPEN A CONNECTION ###################################################
s=socket.socket( )
s.connect((HOST, PORT))
def connect_irc():
    connect_mqtt()
#### SESSION MUST START LIKE THIS ########################################
    s.send("NICK %s\r\n" % NICK)
    s.send("USER %s %s bla :%s\r\n" % (IDENT, HOST, REALNAME))
    time.sleep(3)
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
                if re.match('^[@cmd\w].*$', line[-1]): # if we get a privmsg that starts with "@cmd" , publish it!
                    res = parse_message(str(line))
                    final = ''
                    for i in range(3, len(res)):
                        final = final + str(res[i]) # some UGLY ASS hacks here
                        final = final.replace("'", "")
                        final = final.replace(",", " ")
                    final = final[:-1]
                    final = b64encode(final)
                    print(final)
                    mqsend(final)
                else:
                    pass

            
connect_irc()
listen_irc()

