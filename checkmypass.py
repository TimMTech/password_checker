#Import the Request Library
import requests

#Import the hashlib Library
import hashlib

#Import the sys Library
import sys

#create the url variable and assign it the password api url
#url = 'https://api.pwnedpasswords.com/range/' + 'password123'

#create the response variable and request the url variable
#res = requests.get(url)
#print(res) #response[400] is not good.  Means not authorized


def request_api_data(query_char): #Create a function that recieves API data.
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again.')
    return res

#Create our read response function.
#def read_res(response):
    #print(response.text)

#Create our password leak functuon
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    #print(hashes)
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    #check password if it exists in API response, Convert our password into a Sha1
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper() #Must be encoded or will recieve error 'utf-8'
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    #print(response)
    #return read_res(response)
    return get_password_leaks_count(response, tail)

#request_api_data('123')


#Will Read Passwords from a created txt File.
def main():
    #Accessing passwords from your txt file.
    with open('passkeeper.txt', 'r') as f:  #Opening your created txt file named 'passkeeper.txt'
        passwordlist = []  #create empty list
        for line in f: #loop through each password in the txt file
            content = line.strip()
            passwordlist.append(content)

        for password in passwordlist:
            count = pwned_api_check(password)
            if count:
                print(f'{password} was found {count} times...you should probably change your password')
            else:
                print(f'{password} was NOT found.  Carry on!')
        return 'Done!'


if __name__ == '__main__':
    main()


