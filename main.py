import argparse
import honeypot_ssh
from web import honeypot_web

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser = argparse.ArgumentParser() 
    parser.add_argument('-a','--address', type=str, required=True)
    parser.add_argument('-p','--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-pw', '--password', type=str)

    parser.add_argument('-s', '--ssh', action="store_true")
    parser.add_argument('-wh', '--http', action="store_true")

    args = parser.parse_args()


    if args.ssh:
        print("Running SSH HoneyPot...")
        honeypot_ssh.run(args.address, args.port, args.username, args.password)
    elif args.http:
        print("Running HTTP HoneyPot...")
        honeypot_web.run(args.port, args.username, args.password)
    else:
        print("ERROR: decide to be --ssh or --http (web)")
