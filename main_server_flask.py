from flask import Flask
from flask import request
import os
import signal
import threading
import time

app = Flask(__name__)

@app.route("/")
def home():
    return "Hello, World!"
    
def stopServerFunction(variable):
	for i in range (100):
		for j in range (10000):
			k = j
	sig = getattr( signal, "SIGKILL", signal.SIGTERM)
	os.kill( variable, sig)
    
@app.route("/query")
def query():
    if request.args:

        # We have our query string nicely serialized as a Python dictionary
        args = request.args

        # We'll create a string to display the parameters & values
        serialized = ", ".join(f"{k}: {v}" for k, v in request.args.items())
        # code = request.args[1]
        if args["code"] != None:
            print( args["code"])
            f = open("/home/kmk/Documents/College study materials/Sem 6/TARP/Terlocker_Pro/code.txt", "w")
            f.write(args["code"])
            f.close()
        
        mainProcessID= os.getpid()
        t = threading.Thread( target= stopServerFunction, args= (mainProcessID,))
        t.start()
        # Display the query string to the client in a different format
        return f"(Query) {serialized}.  \n<center><h1>ACCESS GRANTED</h1><center>", 200
    else:
        return "No query string received", 200 


if __name__ == "__main__":
	app.run(host="192.168.115.58", port="8000")
