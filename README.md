# SiFT
Biztonsági protokollok házi feladat

## Virtualenv howto
https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/

### To install all dependencies just run...

```pip install -r requirements.txt```

### Or the following two commands

```pip install pycryptodome```
```pip install aioconsole```

### To start the client application go to /src and run

```./client.py <server public key> ```

### To star the server application go to /src and run

```./server.py keys/privkey```