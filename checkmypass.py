import requests
import hashlib
import sys

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)

    if(res.status_code != 200):
        raise RuntimeError(f' Error fetching: {res.status_code}, check the API and try again')
    return res

""" def read_res(response):
    print(response.text) Got response list """

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())#tuple comprehension
    for h, count in hashes:
        #print(h, count)
        if(h == hash_to_check):
            return count
    return 0

def pwned_api_check(password):
    # check password if it exists in the API response

    #print(hashlib.sha1(password.encode('utf-8'))) sha1 hash obj
    #print(hashlib.sha1(password.encode('utf-8')).hexdigest())converts hash obj to hexidecimal

    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    #print(first5_char, tail)
    response = request_api_data(first5_char)
    #print(response) gave 200 OK but we want the response list of hashed suffixes along with its count, so we can match our suffix
    #return read_res(response)
    return get_password_leaks_count(response, tail)

#read from a text file instead, so it is more secure. cmdl entries are saved (press up arrow)
""" def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times...you should change your password')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'Done!' """
""" if __name__ == '__main__': 
    sys.exit(main(sys.argv[1:])) #ensures program is exited ('done' was not being printed)
 """
def main():
    with open('..\..\..\Desktop\password.txt','r') as my_file:
        for password in my_file:
            count = pwned_api_check(password.strip())
            if count:
                print(f'{password} was found {count} times...you should change your password')
            else:
                print(f'{password} was NOT found. Carry on!')
        my_file.close()
if __name__ == '__main__': 
    sys.exit(main()) #ensures program is exited ('done' was not being printed)


