from pymongo import MongoClient


uri = "mongodb+srv://newUser:89868414@cluster9.m5sn2.mongodb.net/phishguard?retryWrites=true&w=majority&appName=Cluster9"

client = MongoClient(uri)

db = client["phishguard"]
collection = db["scan_results"]


result = collection.delete_many({})

print(f"Видалено документів: {result.deleted_count}")
