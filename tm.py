from pytm import (
    TM, Actor, Boundary, Classification, Data, Dataflow, Datastore, Process, Server
)

tm = TM("My Threat Model")
tm.description = "This is a proof of concept threat model"

publicBoundary = Boundary("Uncontrolled by us")
protectedBoundary = Boundary("Controlled by us")

user = Actor("Customer")
user.inBoundary = publicBoundary

client = Process("Client/GUI")
client.inBoundary = publicBoundary

server = Server("Server")
server.inBoundary = protectedBoundary
server.OS = "MacOS"
server.isHardened = True
server.sanitizesInput = False
server.encodesOutput = True
server.authorizesSource = False

db = Datastore("Database")
db.inBoundary = protectedBoundary
db.OS = "Linux"
db.isHardened = False
dbisSQL = True
db.inScope = True
db.maxClassification = Classification.RESTRICTED

interact = Dataflow(user, client, "Customer accesses the system")

enterData = Dataflow(client, server, "Customer data")
enterData.protocol = "HTTP"
enterData.dstPort = 80
enterData.data = "New items to be stored in JSON format"

saveData = Dataflow(server, db, "Customer data, processed")
saveData.protocol = "SQL"
saveData.dstPort = 3306
saveData.data = "MySQL insert statements, all literals"

loadData = Dataflow(db, server, "Load processed data")
editData = Dataflow(server, client, "Return query results")
present = Dataflow(client, user, "Present data to customer")

tm.process()