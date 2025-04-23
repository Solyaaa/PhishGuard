from pymongo import MongoClient

# Підключення до MongoDB Atlas
uri = "mongodb+srv://newUser:89868414@cluster9.m5sn2.mongodb.net/phishguard?retryWrites=true&w=majority&appName=Cluster9"
client = MongoClient(uri)

# Отримання доступу до бази даних
db = client.phishguard

# Перевірка підключення
print(db.list_collection_names())
