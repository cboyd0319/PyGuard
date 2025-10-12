"""Sample code with bad practices for testing fixes."""


# Mutable default argument
def append_to_list(item, my_list=[]):
    my_list.append(item)
    return my_list


# Bare except clause
def risky_operation():
    try:
        result = 1 / 0
    except:
        pass


# Wrong None comparison
def check_value(x):
    if x == None:
        return "None found"
    return "Value exists"


# Wrong boolean comparison
def is_active(flag):
    if flag == True:
        return "Active"
    return "Inactive"


# Type check instead of isinstance
def process_string(value):
    if type(value) == str:
        return value.upper()
    return None


# Missing docstring
def important_function(a, b):
    return a + b


class ImportantClass:
    def method(self):
        pass


# String concatenation in loop
def build_string(items):
    result = ""
    for item in items:
        result = result + str(item) + ","
    return result


# Not using context manager
def read_file(filename):
    f = open(filename)
    data = f.read()
    f.close()
    return data
