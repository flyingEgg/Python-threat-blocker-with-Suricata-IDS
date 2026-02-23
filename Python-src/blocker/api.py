import os

class API:
    def __init__(self):
        self.key = os.getenv('api_key')
        self.secret = os.getenv('api_secret')