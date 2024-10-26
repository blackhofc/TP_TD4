import argparse
from services.client import Client
from services.server import Server

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='Ejecutar cliente o servidor.')
    
    # Add a required argument for selecting the mode (client or server)
    parser.add_argument(
        '-m', '--mode',
        choices=['client', 'server'],
        required=True,
        help='Especifique si desea ejecutar el cliente o el servidor.'
    )
    
    # Parse the arguments
    args = parser.parse_args()

    # Run the selected mode
    if args.mode == 'client':
        Client().start()
        return

    if args.mode == 'server':
        Server().start()
        return

    print('Modo no válido seleccionado. Seleccione "client" o "server".')

if __name__ == '__main__':
    main()