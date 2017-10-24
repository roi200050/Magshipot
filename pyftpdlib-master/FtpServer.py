from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
 
files_destination = "files"

authorizer = DummyAuthorizer()
authorizer.add_user("user", "12345", files_destination, perm="elradfmw")
authorizer.add_anonymous(files_destination)
 
handler = FTPHandler
handler.authorizer = authorizer
 
server = FTPServer(("0.0.0.0", 21), handler)
server.serve_forever()