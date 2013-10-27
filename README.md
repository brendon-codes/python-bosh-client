Python Bosh Client
==================

Usage
-----

    from bosh_client import BOSHClient
    
    username = "foo"
    password = "bar"
    bosh_url = "http://example.com/bosh"
    client = BOSHClient(username, password, bosh_url)

    if client.logged_in:
        print("Success!")
    else:
        print("Fail!")
    
