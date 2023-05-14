import os
import socket

from multiprocessing import Pipe

# status -1 is DISCONNECTED, 0 is CONNECTED, 1 is AUTHENTICATED
current_status     = -1 
predefined_routers = [("127.0.1.1", 9009)]


def error_message(pipe, message = ""):
    '''
    Prints an error message

    Args:
        message (str): A description of the error to be printed,
                       defaults to an empty string
    '''

    pipe.send(f"[ERROR] {message}\n")


def set_status(status):
    '''
    Defines the current status of an agent

    Args:
        status (int): The current status of the agent
    '''

    global current_status
    current_status = status


def send_status(pipe):
    '''
    Sends current status to app through pipe

    Args:
        pipe (multiprocessing.connection.Connection): Pipe between app and agent
    '''

    pipe.send(current_status)


def send(message):
    '''
    Sends header and message, accordingly, to edge_router

    Args:
        Message (str): message to be sent
    '''

    if message:
        agent.send(message.encode('utf-8'))


def receive():
    '''
    Recieves the incoming message

    Returns:
        (str): The message received
    '''

    message = agent.recv(2048).decode('utf-8') 
    return message



def discover(pipe):
    '''
    Prints predefined list of edge routers if there is one,
    otherwise, it looks for edge routers on the network

    Args:
        pipe (multiprocessing.connection.Connection): Pipe between app and agent
    '''

    if predefined_routers:
        pipe.send(predefined_routers)

    else:
        pipe.send(socket.gethostbyname(socket.gethostname()))


def query(pipe):
    '''
    Queries information about connection

    Args:
        pipe (multiprocessing.connection.Connection): Pipe between app and agent
    '''

    # Only returns status if NOT_CONNECTED
    if current_status == -1:
        pipe.send("NOT_CONNECTED")
    
    else:
        send("!QUERY")
        pipe.send(receive())

    
def connect(pipe):
    '''
    Binds agent to a socket and opens up a two-way byte stream connection

    Args:
        pipe (multiprocessing.connection.Connection): Pipe between app and agent
    '''

    global agent
    agent = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Checks if the agent is connected to the router
    if agent.connect_ex(predefined_routers[0]) == 0:
        set_status(0)
        pipe.send("!ACK")
        send(pipe.recv())
    

def disconnect(pipe): 
    ''' 
    Disconnects agent from edge router

    Args:
        pipe (multiprocessing.connection.Connection): Pipe between app and agent
    ''' 
 
    # Status cannot alreadt be DISCONNECTED
    if current_status != -1: 

        set_status(-1) 
        send("!DISCONNECT")
        
        pipe.send("!ACK")
   
 
def authenticate(pipe): 
    ''' 
    Initiates authentication process between agent and edge router, currently
    that means simply changing the status

    Args:
        pipe (multiprocessing.connection.Connection): Pipe between app and agent
    ''' 
 
    # Status has to be CONNECTED in order to authenticate
    if current_status == 0:
        send("!AUTHENTICATE") 

        if receive() == "!ACK":
            set_status(1)
            pipe.send("!ACK")



def send_message(pipe):
    '''
    Handles sending directed messages.
    Agent choose recipient based on agent list sent by edge router

    Args:
        pipe (multiprocessing.connection.Connection): Pipe between app and agent
    '''

    send("!SEND")

    # Forwards list of active agents to app
    pipe.send(receive())

    # Forwards recipient mrn from app to edge router
    recipient_mrn = pipe.recv()
    send(recipient_mrn)

    # The recipient MRN is valid
    if recipient_mrn != "!ERROR":   

        # Forwards message from app to edge router   
        send(pipe.recv()) 

        if receive() == "!ACK":
            pipe.send("!ACK")

        else:
            pipe.send("!ERROR")


def fetch(pipe):
    '''
    Sends fetch request to the edge router, then forwards the message from the 
    edge router to the app

    Args:
        pipe (multiprocessing.connection.Connection): Pipe between app and agent
    '''

    send("!FETCH")

    # Message 
    pipe.send(receive())


def subscribe(pipe):
    '''
    Sends subscribe request to edge router, receives and sends the
    subject list through the pipe, and then send the mrn of the subject
    to subscribe to to the edge router
    '''

    send("!SUBSCRIBE")

    # Subject list
    pipe.send(receive())

    # Subject MRN
    send(pipe.recv())


def unsubscribe(pipe):
    '''
    Sends unsubscribe request to edge router, receives and sends the
    current subscribtion list through the pipe, and then send the mrn
    of the subject to unsubscribe from to the edge router
    '''

    send("!UNSUBSCRIBE")

    # Subject list
    pipe.send(receive())

    # Subject MRN
    send(pipe.recv())


def start(pipe):
    '''
    Function that runs when an agent process is created by the app.
    Receives commands from app through pipe, and then execute them

    Args:
        pipe (multiprocessing.connection.Connection): pipe between app and agent
    '''

    commands = {
        "status"        : send_status,
        "discover"      : discover,
        "query"         : query,
        "connect"       : connect,
        "disconnect"    : disconnect,
        "authenticate"  : authenticate,
        "send"          : send_message,
        "fetch"         : fetch,
        "subscribe"     : subscribe,
        "unsubscribe"   : unsubscribe
    }

    while pipe.poll(None):
        command = pipe.recv()
        command = command.lower()
        commands.get(command, error_message)(pipe)