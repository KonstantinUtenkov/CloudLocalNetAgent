import uvicorn

import random
import sys
import os

def get_from_env(name, default=None):
    if os.environ.get(name) is not None:
        new_val = os.environ.get(name)
        return new_val
    else:
        return default


SERVER_HOST = get_from_env('HOST', default='0.0.0.0')
SERVER_PORT = get_from_env('PORT', default='7190')


if __name__ == "__main__":
    uvicorn.run("app.api:app", host=SERVER_HOST, port=int(SERVER_PORT), reload=True)
