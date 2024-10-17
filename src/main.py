import argparse
from utils.utils import *
import scripts.client as client
import scripts.server as server

'''
TODO:
- Realiza   r una apertura correctamente
- Realizar un cierre correctamente
- Calcular los porcentajes correspondientes
'''

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='Run client or server.')
    
    # Add a required argument for selecting the mode (client or server)
    parser.add_argument(
        '-m', '--mode',
        choices=['client', 'server'],
        required=True,
        help='Specify whether to run the client or the server.'
    )
    
    # Parse the arguments
    args = parser.parse_args()

    # Run the selected mode
    if args.mode == 'client':
        print('Running client...')
        client.start()
    elif args.mode == 'server':
        print('Running server...')
        server.start()
    else:
        print('Invalid mode selected. Please choose "client" or "server".')

if __name__ == '__main__':
    main()