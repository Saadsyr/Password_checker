import sys,math,re,os

def check_password_length(password):
    length = str(len(password))
    global password_length_good

    if len(password) < 8:
        print ('[!] Warning: password should be at least 8 charchters long')
        print ('[!] Warning: your password is only ',length,' charchters')
        password_length_good = False
    else:
        print ('[*] your password is ',length,' charchters')
        password_length_good = True    


def check_password_uppercase(password):
    global upperlength
    upperlength = len(re.findall(r'[A-Z]',password))

    print('[*] your password contains ',upperlength, ' uppercase charchter')

    if upperlength == 0:
        print("[!] Warning: No Upper case charchter in your password")


def check_password_lowercase(password):
    global lowerlength
    lowerlength = len(re.findall(r'[a-z]',password))

    print('[*] your password contains ',lowerlength, ' lowercase charchter')

    if lowerlength == 0:
        print("[!] Warning: No lower case charchter in your password")


def check_password_numbers(password):
    global digits
    digits = len(re.findall(r'[0-9]',password))

    print ("[*] your password contains ",digits," numeric digit")

    if digits == 0:
        print("[!] Warning: your password has no digits")


def check_password_special_charchter(password):
    global special_charchter
    special_charchter = len(re.findall(r'[@_!#$%^&*()<>?/\|}{~:]',password))
    print ("[*] your password contains ",special_charchter," spcial charchters")

    if special_charchter == 0:
        print("[!] Warning: Your password has no spcial charchters")

def password_eval(password,password_length_good,upperlength,special_charchter,digits,lowerlength):
       print("\n password Evaluation:")

       if password_length_good == True:
           print("[*] Password length is good")
       else:
           print("[!] Password length is bad")

       if upperlength >= 2:
           print("[*] Your password contains good amount of uppercase letters")
       else:
           print("[!] Your password does not contain good amount of uppercase letters")    

       if lowerlength >= 2:
           print("[*] Your password contains good amount of lowercase letters")
       else:
           print("[!] Your password does not contain good amount of lowercase letters")  

       if digits >= 2:
           print("[*] Your password contains good amount of digits")
       else:
           print("[!] Your password does not contain good amount of digits") 

       if special_charchter >= 2:
           print("[*] Your password contains good amount of special charchter")
       else:
           print("[!] Your password does not contain good amount of special charchter")  
     
       if password_length_good == True and upperlength >= 2 and lowerlength >= 2 and digits >= 2 and special_charchter >= 2:
           print("[*] You have a perfect password .. your score is 10/10")
        
       if password_length_good == True and upperlength >= 2 and lowerlength >= 2 and digits >= 2 and not special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 8/10")
       if password_length_good == True and not upperlength >= 2 and lowerlength >= 2 and digits >= 2 and not special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 6/10")    
       if password_length_good == True and upperlength >= 2 and lowerlength >= 2 and not digits >= 2 and  special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 8/10")
       if password_length_good == True and upperlength >= 2 and not lowerlength >= 2 and digits >= 2 and  special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 8/10")
       if password_length_good == False and upperlength >= 2 and lowerlength >= 2 and digits >= 2 and  special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 8/10")
       if password_length_good == True and upperlength >= 2 and lowerlength >= 2 and not digits >= 2 and not special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 6/10") 

       if password_length_good == True and upperlength >= 2 and not lowerlength >= 2 and not digits >= 2 and not special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 4/10") 

       if password_length_good == True and not upperlength >= 2 and not lowerlength >= 2 and not digits >= 2 and not special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 2/10")

       if password_length_good == False and upperlength >= 2 and lowerlength >= 2 and not digits >= 2 and not special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 4/10")
       if password_length_good == False and not upperlength >= 2 and lowerlength >= 2 and digits >= 2 and not special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 4/10")
       if password_length_good == False and not upperlength >= 2 and lowerlength >= 2 and not digits >= 2 and special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 4/10")
                      
       if password_length_good == False and not upperlength >= 2 and lowerlength >= 2 and not digits >= 2 and not special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 2/10")
       if password_length_good == False and upperlength >= 2 and not lowerlength >= 2 and not digits >= 2 and not special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 2/10")
       if password_length_good == False and not upperlength >= 2 and not lowerlength >= 2 and digits >= 2 and not special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 2/10")
                        
       if password_length_good == False and not upperlength >= 2 and not lowerlength >= 2 and not digits >= 2 and not special_charchter >= 2:
           print("[*] Your password is vulnarable .. your score is 0/10")     


def check_pattern(password):
   
    patt=["qwertyuiop",
          "asdfghjkl",
          "zxcvbnm",
          "1234567890",
          "qwert",
          "asd",
          "zxcv",
          "1234",
          "4321",
          "12345",
          "123456",
          "1234567",
          "12345678",
          "qwe",
          "qwer",
          "asdfg",
          "zxcv",
          "zxcvb",
          "zxcvbn",
          "vcxz",
          "bvcxz",
          "fdsa",
          "hgfdsa",
          "987654321",
          "87654321",
          "!@#$",
          "!@#",
          "!@#$%",
          "!@#$%^"]

    
    if password in patt:
        print("[!] Warning: Your password has a bad pattern")
    



def check_dictionary(password):
    script_dir = os.path.dirname(__file__)
    extend = '\\'
    rock = 'rockyou.txt'
    file = open(rock)
    
   
    if(password in file.read()):
        print("[!] Warning: your password is in dictionary wordlist")
    else:
        print("[*] your password is NOT in dictionary wordlist")



def main():
    choose = str(input("\n                    -- Welcome to password meter application -- \n \n                          Made By: Saad Alkhalaf \n \nwhat do you want to do: \n 1- check passowd meter I will give you score out of 10 with some advice to improve your password \n 2- check whether your password is in dictionary wordlist or not\n"))
    
    if choose == "1":

        password = input("Enter your password:  ")
        check_password_length(password)
        check_password_uppercase(password)
        check_password_numbers(password)
        check_password_lowercase(password)
        check_password_special_charchter(password)
        check_pattern(password)
        password_eval(password,password_length_good,upperlength,special_charchter,digits,lowerlength)
        main()
        
    if choose == "2":
        password = input("Enter your password:  ")
        check_dictionary(password)
        main()
    else:
        print('wrong input')
        main()

if __name__== '__main__':
    main()
