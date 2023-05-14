import sys
import smmp
import shutil

from agent            import start
from multiprocessing  import Process, Pipe

def print_help_page():
    '''
    Displays possible commands based on current status
    '''

    status = get_status()
    
    print("\n[HELP PAGE]\n")
    print("\thelp \t\t display available commands\n")
    print("\tstatus \t\t display current status\n")
    print("\tquery \t\t query information about connection\n")
    print("\tdiscover \t discover nearby edge routers\n")
    print("\tconnect \t connect to an edge router\n")

    # Only prints if status is CONNECTED
    if status == 0:
        print("\tauthenticate \t initiate authentication " + "with edge router\n")

    # Only prints if status is CONNECTED or AUTHENTICATED
    if status > -1:
        print("\tsend \t\t send message\n")
        print("\tfetch \t\t fetch message(s)\n")
        print("\tsubscribe \t subscribe to service\n")
        print("\tunsubscribe \t unsubscripbe from service\n")
        print("\tdisconnect \t disconnect from edge router\n")

    print(u"\tquit \n")


def error_message(message = ""):
    '''
    Prints a custom error message

    Args:
        message (str): A description of the error to be printed,
                       defaults to an empty string
    '''

    print(f"[ERROR] {message}\n")

 
def quit_command_line():
    '''
    Terminates the the smmp processes and exits the app
    '''

    finalise()
    sys.exit()


def get_status():
    '''
    Requests the current status code from the agent
    
    Returns:
        int: The status code recieved from the agent
    '''

    pipe.send("status")
    return pipe.recv()


def status():
    '''
    Requests the current status code from the agent,
    and then prints the corresponding status 
    '''

    statuses = ["NOT_CONNECTED", "CONNECTED", "AUTHENTICATED"]
    print(statuses[get_status() + 1])


def discover():
    '''
    Request a list of available edge router from the agent, then
    prints the result
    '''

    pipe.send("discover")
    print(pipe.recv())


def query():
    '''
    Gets the status of the agent
    '''

    pipe.send("query")
    print(pipe.recv())


def connect():
    '''
    Sends a connection command to the agent, and handles the response
    '''

    pipe.send("connect")

    if pipe.recv() == "!ACK":
        print("[CONNECTED]\n")
        pipe.send(smmp.get_mrn())

    else:
        error_message("Could not connect")


def disconnect():
    '''
    Sends a disconnect command to the agent, and handles the response
    '''

    pipe.send("disconnect")

    if pipe.recv() == "!ACK":
        print("[DISCONNECTED]\n")

    else:
        error_message("Could not disconnect")


def authenticate():
    '''
    Sends a authenticate command to the agent, and handles the response
    '''

    pipe.send("authenticate")

    if pipe.recv() == "!ACK":
        print("[AUTHENTICATED]\n")

    else:
        error_message("Could not authenticate")



def get_recipient_mrn():
    '''
    Retrieves a list of active agents from the edge router, presents
    them to the user, and then the user chooses a recipient
    
    Returns:
        str: MRN of the chosen subject, or False if the
             user input is invalid
    '''

    # Recieves list of available agents from edge router
    active_agents = pipe.recv()[13:-2].split(", ")
    
    print(f"\nList of active agents:")
    
    # Prints a numbered list of active agents mrn
    counter = 1
    for agent in active_agents:
        print(f"\t{counter}. {agent[1:-1]}")
        counter += 1

    # User enters list number of recipient
    agent_num = input("\nEnter number of agent you want to message: ")

    # User did not enter valud number
    if not agent_num.isdigit() or int(agent_num) not in range(1, counter):
        error_message("Invalid number. Please enter valid number")
        return False
    
    # Returns the mrn of the message recipient
    return active_agents[int(agent_num) - 1][1:-1]
    

def send():
    '''
    Sends a message to another agent via the edge router.

    Function gets recipient, and if the recipient is valid, 
    the user enters a message.It then encrypts and signs the 
    message, and sends it to the edge router
    '''

    if get_status() == -1:
        error_message("Cannot send message when DISCONNECTED")

    else:
        pipe.send("send")

        # Recipient mrn if user entered valid anwer, otherwise False
        recipient_mrn = get_recipient_mrn()
        
        if recipient_mrn:
            pipe.send(recipient_mrn)

            # User enters message, the message is then encrypted, signed and sent
            message = input("Message: ")
            encrypted_message = smmp.encrypt_and_sign(message, recipient_mrn)
            pipe.send(encrypted_message)
            
            # Edge router response
            response = pipe.recv() 
            
            if response != "!ACK":
                error_message("Could not send message")
        
        else:
            pipe.send("!ERROR")


def fetch():
    '''
    Fetches a message from the edge router, if there is any. Then the function
    decrypts and verifies the message
    '''

    if get_status() == -1:
        error_message("Cannot fetch message when DISCONNECTED")

    else:
        # Gets a message from the edge router
        pipe.send("fetch")
        encrypted_message = pipe.recv() 

        # Message queue is not empty
        if encrypted_message != "!ERROR":

            # Decrypts the message and checks the digital signature
            sender_mrn, message = smmp.decrypt_and_verify(encrypted_message)

            # Digital signature valid
            if message:
                print(f"\n[MESSAGE FROM {sender_mrn}]\n\n{message}\n")

            # Digital signature not valid
            else:
                error_message("Digital signature could not be verified")

        # Message queue is empty  
        else:
            error_message("No messages to be fetched")


def get_subject_mrn(subject_list):
    '''
    Takes list of subjects from the edge router, presents
    them to the user, and then the user chooses a subject

    Args:
        subject_list (list[str]): List of subjects
    
    Returns:
        str: MRN of the chosen subject, or False if there
             subject list is empty of user input is invalid
    '''

    print(f"\nList of subjects:")
    counter = 1
    
    # Prints a numbered list of subjects
    for subject in subject_list:

        # Checks if the list is empty
        if len(subject) == 0:
            error_message("Subject list is empty")
            pipe.send("!ERROR")
            return False

        print(f"\t{counter}. {subject[1:-1]}")
        counter += 1

    # User enters number of the subject mrn
    subject_num = input("\nEnter number of subject: ")

    # User did not enter valid number
    if not subject_num.isdigit() or int(subject_num) not in range(1, counter):
        error_message("Invalid number")
        return False
    
    # Returns the mrn of chosen subject
    return subject_list[int(subject_num) - 1][1:-1]


def subscribe():
    '''
    Gets list of availbale subjects, then subscibes agent to a subject
    '''

    if get_status() == -1:
        error_message("Cannot subscribe when DISCONNECTED")

    else:
        pipe.send("subscribe")

        # Gets the list of available subject mrns
        subject_list = pipe.recv()[11:-2].split(", ")

        # Gets the mrn of the subject to subscribe to
        subject_mrn = get_subject_mrn(subject_list)

        if subject_mrn:
            pipe.send(subject_mrn)
        
        else:
            pipe.send("!ERROR")



def unsubscribe():
    '''
    Gets list of subjects the agent is subscribed to, then 
    unsubscribes agent from subject
    '''

    if get_status() == -1:
        error_message("Cannot unsubscribe when DISCONNECTED")

    else:
        pipe.send("unsubscribe")

        # Gets the list of the mrns of the subjects the agent is subscribed to
        subject_list = pipe.recv()[1:-1].split(", ")

        # Gets the mrn of the subject to unsubscribe from
        subject_mrn = get_subject_mrn(subject_list)

        if subject_mrn:
            pipe.send(subject_mrn)


def command_line():
    '''
    Displays the command line interface for agent functionalities
    and executes valid commands from the app and smmp
    '''

    print("Type help to show available commands.\n")

    commands = {
        "quit"          : quit_command_line,
        "help"          : print_help_page,        
        "status"        : status,
        "discover"      : discover,
        "query"         : query,
        "connect"       : connect,
        "disconnect"    : disconnect,
        "authenticate"  : authenticate,
        "send"          : send,
        "fetch"         : fetch,
        "subscribe"     : subscribe,
        "unsubscribe"   : unsubscribe
    }

    while True:
        print(" ")
        command = input("> ")
        command = command.lower()
        
        if command in commands:
            commands.get(command)()
        
        else:
            print("[Invalid command]")
        

def finalise():
    '''
    Terminates the agent process
    '''

    shutil.rmtree("keys/")
    process.terminate()


def init():
    '''
    Creates a pipe between the app and agent, creates and 
    starts an agent process, and generates an ECC key-pair
    '''
    
    global pipe
    pipe, pipe_agent = Pipe()

    global process
    process = Process(target = start, args = (pipe_agent,)) 
    process.start()

    # Sets the agent MRN
    smmp.set_mrn(process.pid)

    # Genereates a key-pair
    smmp.generate_private_key()
    smmp.generate_public_key()

    print(f"\n[AGENT API] [Logged in as: {smmp.get_mrn()}]\n")
 

if __name__ == "__main__":
    init()
    command_line()
