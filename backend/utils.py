
import json
from bson import ObjectId
from datetime import datetime


class JSONEncoder(json.JSONEncoder):
    """
    Розширений JSON енкодер для правильної серіалізації ObjectId та datetime.
    """

    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


