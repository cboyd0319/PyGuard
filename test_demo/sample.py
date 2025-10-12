import os
import yaml
import pickle

# Security issues
password = "my_secret_password_123"
api_key = "sk-1234567890abcdef"

def unsafe_code():
    # Command injection risk
    user_input = input("Enter command: ")
    os.system(user_input)
    
    # Code injection
    code = input("Enter code: ")
    eval(code)
    
    # Unsafe deserialization
    with open("data.yaml") as f:
        data = yaml.load(f)
    
    with open("data.pkl", "rb") as f:
        obj = pickle.load(f)

# Best practices issues
def bad_function(items=[]):
    if x == None:
        pass
    if y == True:
        pass

def long_function():
    x = 10
    for i in range(100):
        if i % 2 == 0:
            if i % 3 == 0:
                if i % 5 == 0:
                    print(i)
