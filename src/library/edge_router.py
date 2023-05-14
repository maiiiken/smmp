import socket 
import threading

SERVER   = socket.gethostbyname(socket.gethostname())
PORT     = 9009
ADDRESS  = (SERVER, PORT)

edge_router = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
edge_router.bind(ADDRESS)

active_agents = {}
message_queue = {}
subscriptions = {"urn:mrn:mcp:service:ipid:1": [],
                 "urn:mrn:mcp:service:ipid:2": [],
                 "urn:mrn:mcp:service:ipid:3": [],
                 "urn:mrn:mcp:service:ipid:4": [],
                 "urn:mrn:mcp:service:ipid:5": []}    


def error_message(message = ""):
    '''
    Prints an error message

    Args:
        message (str): A description of the error to be printed,
                       defaults to an empty string
    '''

    print(f"[ERROR] {message}\n")


def send(connection, message):
    '''
    Function sending message to agent

    Args:
        connection (socket.socket): Connection to agent
        message (str): Message to be sent
    '''
    
    if message:
        connection.send(message.encode('utf-8'))

    else:
        error_message("Invalid input: The message is empty")


def receive(connection):
    '''
    Receives the incoming message

    Args:
        connection (socket.socket): Connection to agent

    Returns:
        (str): message received
    '''
   
    message = connection.recv(2048).decode('utf-8')

    if message:
        return message
    
    else:
        error_message("Message recieved is empty")


def queue_add(reciptient_mrn, message):
    '''
    Appends message to queue

    Args:
        mrn (str): mrn of recipient
        message (str): Message to be sent
    '''

    if reciptient_mrn not in message_queue:
        message_queue[reciptient_mrn] = []
    
    message_queue[reciptient_mrn].append(message)


def queue_get(recipient_mrn):
    '''
    Gets directed message from queue, then deletes message
    from the queue

    Args:
        connection (socket.socket): Connection to agent

    Returns:
        (str): Directed message
    '''

    if recipient_mrn in message_queue and message_queue[recipient_mrn]:
        return message_queue[recipient_mrn].pop(0)
    
    else:
        return None


def query(connection):
    '''
    Sends information about the current connection to agent

    Args:
        connection (socket.socket): Connection to agent
    '''

    send(connection, str(connection))


def authenticate(connection):
    '''
    Authenticates the agent (the actual authentication process will
    be handled elsewhere)

    Args:
        connection (socket.socket): Connection to agent
    '''
    
    send(connection, "!ACK")
    

def send_message(connection):
    '''
    Handles receiving directed messages from agents and adds them to a queue

    Args:
        connection (socket.socket): Connection to agent
    '''

    # Sends a list of the mrns of active agents
    send(connection, str(active_agents.values()))

    reciptient_mrn = receive(connection)

    if reciptient_mrn != "!ERROR":
        message = receive(connection)
        queue_add(reciptient_mrn, message)
        send(connection, "!ACK")

 

def fetch_message(connection):
    '''
    Handles sending directed messages to agents from the message queue.
    Queue works as a FIFO (first-in-first-out) queue

    Args:
        connection (socket.socket): Connection to agent
    '''

    agent_mrn = active_agents[connection]

    # Checks if there are any messages for the agent
    if agent_mrn in message_queue and message_queue[agent_mrn]:
        message = str(queue_get(agent_mrn))    
        send(connection, message)
        
    else:
        send(connection, "!ERROR")


def subscribe(connection):
    '''
    Adds an agent to the subscription list for a specified subject

    This function sends a list of available subjects to the agent, then 
    receives the subject MRN that the agent wishes to subscribe to.
    If the subject MRN exists in the list of subscriptions, the agent 
    is added to the list 

    Args:
        connection (socket.socket): Connection to agent
    '''

    agent_mrn = active_agents[connection]

    # Sends a list of available subjects to the agent
    send(connection, str(subscriptions.keys()))

    subject_mrn = receive(connection)

    if subject_mrn in subscriptions:
        subscriptions[subject_mrn].append(agent_mrn)


def unsubscribe(connection):
    '''
    Removes an agent from the subscription list of a specified subject

    This function finds all the subjects that the agent is currently subscribed to,
    sends this list to the agent, then receives the subject MRN that the agent wishes 
    to unsubscribe from. If the subject MRN exists in the list of subscriptions, the 
    agent is removed from the list of subscribers for that subject

    Args:
        connection (socket.socket): Connection to agent
    '''

    agent_mrn = active_agents[connection]

    # Finds subjects the agent is subscribed to
    current_subscriptions = []

    for subject_mrn, agents in subscriptions.items():

        if agent_mrn in agents:
            current_subscriptions.append(subject_mrn)

    send(connection, str(current_subscriptions))
    subject_mrn = receive(connection)

    if subject_mrn in subscriptions:
        subscriptions[subject_mrn].remove(agent_mrn)


def agent_thread(connection, address):
    '''
    Function that starts a new thread with a connection to an agent

    Args:
        connection (socket.socket): Connection to agent
        address (tuple):            Address of agent
    '''

    commands = {            
        "!QUERY"         : query,
        "!AUTHENTICATE"  : authenticate,
        "!SEND"          : send_message,
        "!FETCH"         : fetch_message,
        "!SUBSCRIBE"     : subscribe,
        "!UNSUBSCRIBE"   : unsubscribe
    }

    # Recieves the agent MRN and adds it to the list of active agents
    agent_mrn = receive(connection)
    active_agents.update({connection: agent_mrn})

    print(f"\n{agent_mrn} connected to edge router\n")

    connected = True
    while connected:
        message = receive(connection)

        if message in commands:
            commands.get(message)(connection)

        elif message == "!DISCONNECT":
            connection.close()
            connected = False
        
        else:
            connected = False

    active_agents.pop(connection)

        
def open_socket():
    '''
    Opens a socket and continously listen for incoming connections.
    For every incoming connection, a new thread is created
    '''

    print("[EDGE ROUTER ACTIVE]\n")
    edge_router.listen()

    while True:
        connection, address = edge_router.accept()
        thread = threading.Thread(target=agent_thread, args=(connection, address))
        thread.start()


if __name__ == "__main__":
    open_socket()