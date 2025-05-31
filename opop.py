from pymongo import MongoClient

# 🔐 Замініть на ваш рядок підключення з MongoDB Atlas
uri = "mongodb+srv://newUser:89868414@cluster9.m5sn2.mongodb.net/phishguard?retryWrites=true&w=majority&appName=Cluster9"

client = MongoClient(uri)

# Вибір бази даних і колекції
db = client["phishguard"]
collection = db["scan_results"]

# Видалення всіх документів
result = collection.delete_many({})

print(f"Видалено документів: {result.deleted_count}")
