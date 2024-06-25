from tkinter import *
from tkinter import messagebox
import mysql.connector as mysql
from subprocess import call
import subprocess
import pyperclip
import webbrowser
import bcrypt
import random
import string
from cryptography.fernet import Fernet
import secrets
import time
import os

db= mysql.connect(host="localhost", user="root", password="5hubh@mysql#r00t",database="pythonmini")
cursor=db.cursor()

# def generate_fernet_key():
#     key = Fernet.generate_key()
#     return key

# global encryption_key
# encryption_key = generate_fernet_key()

def get_encryption_key():
    key_file = 'encryption_key.key'
    try:
        if os.path.exists(key_file):
            # Key exists, load it from file
            with open(key_file, 'rb') as f:
                encryption_key = f.read()
        else:
            encryption_key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(encryption_key)
        return encryption_key
    except Exception as e:
        print(f"Error while loading/generating encryption key: {e}")
        return None

# Load or generate the encryption key
encryption_key = get_encryption_key()

# Check if encryption key is successfully loaded/generated
if encryption_key is None:
    print("Encryption key not available. Exiting program.")
    exit()

# print(encryption_key)
# time.sleep(5)


def callgeneratepwdwindow():
    def goback():
        pgenroot.destroy()
        callmainwindow()
    
    root.destroy()
    def generate_password(length, lowercase, uppercase, numbers, punctuation):
        characters = ''
        if lowercase:
            characters += string.ascii_lowercase
        if uppercase:
            characters += string.ascii_uppercase
        if punctuation:
            characters += string.punctuation
        
        if numbers:
            characters += string.digits
            length -= 1  
        
        password = ''.join(random.choice(characters) for _ in range(length))
        
        # Insert a random digit at a random position
        if numbers:
            random_digit = random.choice(string.digits)
            random_position = random.randint(0, len(password))
            password = password[:random_position] + random_digit + password[random_position:]
        
        return password

    def copy_to_clipboard():
        pyperclip.copy(password_entry.get())
        messagebox.showinfo("Copy Status", "Copy Successful")

    def show():
        length = int(length_scale.get())
        lowercase = lowercase_var.get()
        uppercase = uppercase_var.get()
        numbers = numbers_var.get()
        punctuation = punctuation_var.get()

        password = generate_password(length, lowercase, uppercase, numbers, punctuation)
        password_entry.delete(0, END)
        password_entry.insert(0, password)

    pgenroot = Tk()
    pgenroot.geometry('400x350+430+100')
    pgenroot.minsize(400, 350)
    pgenroot.maxsize(400, 350)
    pgenroot.title("Password Generator")
    pgenroot.configure(bg='#dfe6e9')  # Change background color

    # Title Label
    title_label = Label(pgenroot, text="Password Generator", font=('Helvetica', 20, 'bold'), bg='#dfe6e9')
    title_label.place(relx=0.5, rely=0.05, anchor='center')

    label1 = Label(pgenroot, text="Select length of password", font=('Helvetica', 10), bg='#dfe6e9')
    label1.place(x=130, y=60)

    length_scale = Scale(pgenroot, from_=6, to=16, orient=HORIZONTAL, length=300)
    length_scale.place(x=50, y=90)

    lowercase_var = IntVar()
    lowercase_checkbox = Checkbutton(pgenroot, text="Lowercase", variable=lowercase_var, font=('Helvetica', 10), bg='#dfe6e9')
    lowercase_checkbox.place(x=100, y=130)

    uppercase_var = IntVar()
    uppercase_checkbox = Checkbutton(pgenroot, text="Uppercase", variable=uppercase_var, font=('Helvetica', 10), bg='#dfe6e9')
    uppercase_checkbox.place(x=200, y=130)

    numbers_var = IntVar()
    numbers_checkbox = Checkbutton(pgenroot, text="Numbers", variable=numbers_var, font=('Helvetica', 10), bg='#dfe6e9')
    numbers_checkbox.place(x=100, y=160)

    punctuation_var = IntVar()
    punctuation_checkbox = Checkbutton(pgenroot, text="Punctuation", variable=punctuation_var, font=('Helvetica', 10), bg='#dfe6e9')
    punctuation_checkbox.place(x=200, y=160)

    genpwdbutton = Button(pgenroot, text="Generate", border=3, command=show, font=('Helvetica', 12), bg='#55efc4')
    genpwdbutton.place(x=160, y=200)

    password_entry = Entry(pgenroot, width=30, font=('Arial', 15), border=3, justify=CENTER)
    password_entry.place(x=30, y=240)

    copypwdbutton = Button(pgenroot, text="COPY", border=0, command=copy_to_clipboard, width=5, font=('Arial', 10), activebackground="#0984e3", activeforeground="white")
    copypwdbutton.place(x=180, y=290)


    backbutton=Button(pgenroot,text="Back",fg='white',bg='black',border=3,command=goback)
    backbutton.place(x=10,y=10)

    pgenroot.mainloop()

def manage_password(action, user, root_pwd, cursor, pwd_type):
    if action == "add":
        def checknadd():
            usernamefornewpwd = e_entnewuser.get()
            newenteredpwd = e_entnewpwd.get()
            confirmnewpwd = e_entconfirmnewpwd.get()
            if usernamefornewpwd == user:
                if newenteredpwd == confirmnewpwd:
                    if newenteredpwd == root_pwd:
                        messagebox.showwarning("Password Status", "Password cannot be same as the root password")
                    else:
                        cipher = Fernet(encryption_key)
                        #encrypted_password = cipher.encrypt(newenteredpwd.encode())
                        encrypted_password = cipher.encrypt(newenteredpwd.encode()).decode('utf-8').strip()
                        cursor.execute(f"UPDATE {usernamefornewpwd} SET {pwd_type} = '{encrypted_password}'")
                        cursor.execute("COMMIT")
                        messagebox.showinfo("Password Status", "Password added successfully")
                        newpwd.destroy()
                else:
                    messagebox.showerror("Password Status", "Password not matching")
            else:
                messagebox.showerror("Password Status", "Username not matching")

        cursor.execute(f"SELECT {pwd_type} FROM {user}")
        fetched_password = cursor.fetchone()
        fetchedpassword = fetched_password[0]
        cipher = Fernet(encryption_key)
        if fetchedpassword is None:
            newpwd = Tk()
            newpwd.geometry('350x200+500+200')
            newpwd.minsize(350, 200)
            newpwd.maxsize(350, 200)
            newpwd.title("Add Password")
            newpwd['background']='#ecb9fa'

            newusername = Label(newpwd, text='Enter username:')
            newusername.place(x=20, y=20)

            newuserpassword = Label(newpwd, text='Enter password:')
            newuserpassword.place(x=20, y=50)

            confirmnewpassword = Label(newpwd, text='Confirm password:')
            confirmnewpassword.place(x=20, y=80)

            e_entnewuser = Entry(newpwd, font=('Open Sans', 10), border=3)
            e_entnewuser.place(x=150, y=20, width=150)

            e_entnewpwd = Entry(newpwd, font=('Open Sans', 10), border=3, show='*')
            e_entnewpwd.place(x=150, y=50, width=150)

            e_entconfirmnewpwd = Entry(newpwd, font=('Open Sans', 10), border=3, show='*')
            e_entconfirmnewpwd.place(x=150, y=80, width=150)

            gaddpwdbutton = Button(newpwd, width=10, text="Add", border=3, command=checknadd)
            gaddpwdbutton.place(x=130, y=150)
        else:
            messagebox.showerror("Password Status", "Password already exists")

    elif action == "modify":
        def checknmodify():
            origpwd = e_originalpwd.get()
            modifiedpwd = e_modifiedpwd.get().strip()
            confirmmodpwd = e_confirmmodifiedpwd.get().strip()
            usernameformodify = e_musername.get()
            cursor.execute(f"SELECT security_key FROM {user}")
            fetched_seckey = cursor.fetchone()
            # fetchedseckey = fetched_seckey[0]
            cipher = Fernet(encryption_key)
            fetchedseckey = cipher.decrypt(fetched_seckey[0].encode()).decode().strip()
            enteredseckey = e_mseckey.get().strip()
            if usernameformodify == user:
                if(fetchedseckey==enteredseckey):
                    cursor.execute(f"SELECT {pwd_type} FROM {user}")
                    fetched_password = cursor.fetchone()
                    #fetchedpassword = fetched_password[0]
                    cipher = Fernet(encryption_key)
                    fetchedpassword = cipher.decrypt(fetched_password[0].encode()).decode().strip()
                    if fetchedpassword == origpwd:
                        if modifiedpwd == confirmmodpwd:
                            if origpwd == modifiedpwd:
                                messagebox.showwarning("Password Status", "New Password cannot be the same as the old password!")
                            elif root_pwd == modifiedpwd:
                                messagebox.showwarning("Password Status", "New Password cannot be the same as the root password!")
                            else:
                                cipher = Fernet(encryption_key)
                                #encrypted_password = cipher.encrypt(modifiedpwd.encode())
                                encrypted_password = cipher.encrypt(modifiedpwd.encode()).decode('utf-8').strip()
                                cursor.execute(f"UPDATE {usernameformodify} SET {pwd_type} = '{encrypted_password}'")
                                cursor.execute("COMMIT")
                                modpwd.destroy()
                                messagebox.showinfo("Password Status", "Password Successfully Modified!")
                        else:
                            messagebox.showerror("Password Status", "Passwords do not match")
                    else:
                        messagebox.showerror("Password Status", "Original Password not matching!")
                else:
                    messagebox.showerror("Password Status","Security key doesnt't match")
            else:
                messagebox.showerror("Password Status", "Username not matching!")
            # url='https://www.netflix.com/in/login'
            # webbrowser.open_new(url)

        global modpwd
        modpwd = Tk()
        modpwd.geometry('350x250+500+200')
        modpwd.title("Modify Password")
        modpwd.minsize(350, 250)
        modpwd.maxsize(350, 250)
        modpwd['background']='#ecb9fa'

        musername = Label(modpwd, text='Username:')
        musername.place(x=20, y=20)

        originalpwd = Label(modpwd, text='Original password:')
        originalpwd.place(x=20, y=50)

        modifieduserpassword = Label(modpwd, text='New password:')
        modifieduserpassword.place(x=20, y=80)

        confirmmodifiedpassword = Label(modpwd, text='Confirm new password:')
        confirmmodifiedpassword.place(x=20, y=110)

        securitykey=Label(modpwd, text="Enter Security Key:")
        securitykey.place(x=20,y=140)

        e_musername = Entry(modpwd, font=('Open Sans', 10), border=3)
        e_musername.place(x=150, y=20, width=150)

        e_originalpwd = Entry(modpwd, font=('Open Sans', 10), border=3, show='*')
        e_originalpwd.place(x=150, y=50, width=150)

        e_modifiedpwd = Entry(modpwd, font=('Open Sans', 10), border=3, show='*')
        e_modifiedpwd.place(x=150, y=80, width=150)

        e_confirmmodifiedpwd = Entry(modpwd, font=('Open Sans', 10), border=3, show='*')
        e_confirmmodifiedpwd.place(x=150, y=110, width=150)

        e_mseckey = Entry(modpwd, font=('Open Sans', 10), border=3, show='*')
        e_mseckey.place(x=150, y=140, width=150)

        gmodpwdbutton = Button(modpwd, width=15, text="Check and Modify", border=3, command=checknmodify)
        gmodpwdbutton.place(x=130, y=170)

    elif action == "copy":
        def checksecuritykey():
            cursor.execute(f"SELECT security_key FROM {user}")
            fetched_seckey = cursor.fetchone()
            # fetchedseckey = fetched_seckey[0]
            cipher = Fernet(encryption_key)
            fetchedseckey = cipher.decrypt(fetched_seckey[0].encode()).decode().strip()
            enteredseckey = e_seckey.get().strip()
            cursor.execute(f"SELECT {pwd_type} FROM {user}")
            fetched_password = cursor.fetchone()
            fetchedpassword = fetched_password[0]
            cipher = Fernet(encryption_key)
            # fetchedpassword = cipher.decrypt(fetched_password [0]).decode()
            
            if fetchedpassword is None:
                seckeyroot.destroy()
                messagebox.showerror("Copy Status", "Password does not exist")
            else:
                fetchedpassword = cipher.decrypt(fetched_password[0].encode()).decode().strip()
                if enteredseckey == fetchedseckey:
                    seckeyroot.destroy()
                    pyperclip.copy(fetchedpassword)
                    messagebox.showinfo("Copy Status", "Copy Successful")
                else:
                    seckeyroot.destroy()
                    messagebox.showerror("Copy Status", "Security key doesn't match")

        def handle_check():
            checksecuritykey()
        global seckeyroot
        seckeyroot = Tk()
        seckeyroot.geometry("350x100+525+400")
        seckeyroot.minsize(350, 100)
        seckeyroot.maxsize(350, 100)
        seckeyroot.title("Security Key")

        seckey = Label(seckeyroot, text="Enter Security Key: ")
        seckey.place(x=20, y=10)

        global e_seckey
        e_seckey = Entry(seckeyroot, font=('Open Sans', 10), border=3,show="*")
        e_seckey.place(x=150, y=10, width=150)

        cbutton = Button(seckeyroot, width=4, text="Check", border=3, command=handle_check)
        cbutton.place(x=150, y=50)

def addpwd(pwd_type):
    manage_password("add", user, root_pwd, cursor, pwd_type)

def modifypwd(pwd_type):
    manage_password("modify", user, root_pwd, cursor, pwd_type)

def copypwd(pwd_type):
    manage_password("copy", user, root_pwd, cursor, pwd_type)


def callmypwd():
    root.destroy()
    # call(['python','mypwd.py'])
    ###########################################GOOGLE WINDOW######################################################
    def callgooglewindow():
        def gback():
            googleroot.destroy()
            mypwdrootwindow()
            
        def g_addpwd():
            addpwd(pwd_type="gpwd")
        def g_modpwd():
            modifypwd(pwd_type="gpwd")
        def g_copypwd():
            copypwd(pwd_type="gpwd")

        mypwdroot.destroy()
        # call(['python','googleacc.py'])
        googleroot=Tk()
        googleroot.geometry('400x400+435+80')
        googleroot.title("Google Password")

        gbackgroundimage=PhotoImage(file='Images\googlepwdimage.png')
        glabel1=Label(googleroot,image=gbackgroundimage)
        glabel1.pack()
        gaddpwdbutton=Button(googleroot,width=12,height=3,text="ADD",font=('Arial',10),border=3,command=g_addpwd)
        gaddpwdbutton.place(x=50,y=100)

        gmodifypwdbutton=Button(googleroot,width=12,height=3,text="MODIFY",font=('Arial',10),border=3,command=g_modpwd)
        gmodifypwdbutton.place(x=50,y=200)

        gcopypwdbutton=Button(googleroot,width=12,height=3,text="COPY",font=('Arial',10),border=3,command=g_copypwd)
        gcopypwdbutton.place(x=50,y=300)

        gbackbutton=Button(googleroot,text="Back",font=('Arial',10),fg='white',bg='black',border=3,command=gback)
        gbackbutton.place(x=20,y=30)
        googleroot.mainloop()


    ####################################NETFLIX WINDOW###########################################################
    def callnetflixwindow():
        def nback():
            netflixroot.destroy()
            mypwdrootwindow()
        
        def n_addpwd():
            addpwd(pwd_type="npwd")
        def n_modpwd():
            modifypwd(pwd_type="npwd")
        def n_copypwd():
            copypwd(pwd_type="npwd")

        mypwdroot.destroy()
        # call(['python','netflixacc.py'])
        netflixroot=Tk()
        netflixroot.geometry('400x400+435+80')
        netflixroot.title("Netflix Password")

        nbackgroundimage=PhotoImage(file='Images/netflixpwdimage.png')
        nlabel1=Label(netflixroot,image=nbackgroundimage)
        nlabel1.pack()
        naddpwdbutton=Button(netflixroot,width=12,height=3,text="ADD",font=('Arial',10),border=3,command=n_addpwd)
        naddpwdbutton.place(x=50,y=100)

        nmodifypwdbutton=Button(netflixroot,width=12,height=3,text="MODIFY",font=('Arial',10),border=3,command=n_modpwd)
        nmodifypwdbutton.place(x=50,y=200)

        ncopypwdbutton=Button(netflixroot,width=12,height=3,text="COPY",font=('Arial',10),border=3,command=n_copypwd)
        ncopypwdbutton.place(x=50,y=300)

        nbackbutton=Button(netflixroot,text="Back",font=('Arial',10),fg='white',bg='black',border=3,command=nback)
        nbackbutton.place(x=20,y=30)
        netflixroot.mainloop()

    ####################################INSTAGRAM WINDOW###########################################################
    def callinstawindow():
        def iback():
            instaroot.destroy()
            mypwdrootwindow()

        def i_addpwd():
            addpwd(pwd_type="ipwd")
        def i_modpwd():
            modifypwd(pwd_type="ipwd")
        def i_copypwd():
            copypwd(pwd_type="ipwd")

        mypwdroot.destroy()
        # call(['python','instaacc.py'])
        instaroot=Tk()
        instaroot.geometry('400x400+435+80')
        instaroot.title("Instagram Password")

        ibackgroundimage=PhotoImage(file='Images\instapwdimage.png')
        ilabel1=Label(instaroot,image=ibackgroundimage)
        ilabel1.pack()
        iaddpwdbutton=Button(instaroot,width=12,height=3,text="ADD",font=('Arial',10),border=3,command=i_addpwd)
        iaddpwdbutton.place(x=50,y=100)

        imodifypwdbutton=Button(instaroot,width=12,height=3,text="MODIFY",font=('Arial',10),border=3,command=i_modpwd)
        imodifypwdbutton.place(x=50,y=200)

        icopypwdbutton=Button(instaroot,width=12,height=3,text="COPY",font=('Arial',10),border=3,command=i_copypwd)
        icopypwdbutton.place(x=50,y=300)

        ibackbutton=Button(instaroot,text="Back",font=('Arial',10),fg='white',bg='black',border=3,command=iback)
        ibackbutton.place(x=20,y=30)
        instaroot.mainloop()

    ####################################LINKEDIN WINDOW###########################################################
    def calllinkwindow():
        def lback():
            linkedinroot.destroy()
            mypwdrootwindow()
        
        def l_addpwd():
            addpwd(pwd_type="lpwd")
        def l_modpwd():
            modifypwd(pwd_type="lpwd")
        def l_copypwd():
            copypwd(pwd_type="lpwd")

        mypwdroot.destroy()
        # call(['python','linkacc.py'])
        linkedinroot=Tk()
        linkedinroot.geometry('400x400+435+80')
        linkedinroot.title("LinkdeIn Password")

        lbackgroundimage=PhotoImage(file='Images\linkpwdimage.png')
        llabel1=Label(linkedinroot,image=lbackgroundimage)
        llabel1.pack()
        laddpwdbutton=Button(linkedinroot,width=12,height=3,text="ADD",font=('Arial',10),border=3,command=l_addpwd)
        laddpwdbutton.place(x=50,y=100)

        lmodifypwdbutton=Button(linkedinroot,width=12,height=3,text="MODIFY",font=('Arial',10),border=3,command=l_modpwd)
        lmodifypwdbutton.place(x=50,y=200)

        lcopypwdbutton=Button(linkedinroot,width=12,height=3,text="COPY",font=('Arial',10),border=3,command=l_copypwd)
        lcopypwdbutton.place(x=50,y=300)

        lbackbutton=Button(linkedinroot,text="Back",font=('Arial',10),fg='white',bg='black',border=3,command=lback)
        lbackbutton.place(x=20,y=30)

        linkedinroot.mainloop()

    ####################################FACEBOOK WINDOW###########################################################
    def callfacebookwindow():
        def fback():
            facebookroot.destroy()
            mypwdrootwindow()
        
        def f_addpwd():
            addpwd(pwd_type="fpwd")
        def f_modpwd():
            modifypwd(pwd_type="fpwd")
        def f_copypwd():
            copypwd(pwd_type="fpwd")

        mypwdroot.destroy()
        # call(['python','facebookacc.py'])
        facebookroot=Tk()
        facebookroot.geometry('400x400+435+80')
        facebookroot.title("Facebook Password")

        fbackgroundimage=PhotoImage(file='Images/facebookpwdimage.png')
        flabel1=Label(facebookroot,image=fbackgroundimage)
        flabel1.pack()
        faddpwdbutton=Button(facebookroot,width=12,height=3,text="ADD",font=('Arial',10),border=3,command=f_addpwd)
        faddpwdbutton.place(x=50,y=100)

        fmodifypwdbutton=Button(facebookroot,width=12,height=3,text="MODIFY",font=('Arial',10),border=3,command=f_modpwd)
        fmodifypwdbutton.place(x=50,y=200)

        fcopypwdbutton=Button(facebookroot,width=12,height=3,text="COPY",font=('Arial',10),border=3,command=f_copypwd)
        fcopypwdbutton.place(x=50,y=300)

        obackbutton=Button(facebookroot,text="Back",font=('Arial',10),fg='white',bg='black',border=3,command=fback)
        obackbutton.place(x=20,y=30)

        facebookroot.mainloop()

    ####################################OFFICE WINDOW###########################################################
    def callofficewindow():
        def oback():
            officeroot.destroy()
            mypwdrootwindow()

        def o_addpwd():
            addpwd(pwd_type="opwd")
        def o_modpwd():
            modifypwd(pwd_type="opwd")
        def o_copypwd():
            copypwd(pwd_type="opwd")

        mypwdroot.destroy()
        # call(['python','officeacc.py'])
        officeroot=Tk()
        officeroot.geometry('400x400+435+80')
        officeroot.title("Office Password")

        obackgroundimage=PhotoImage(file='Images\officepwdimage.png')
        olabel1=Label(officeroot,image=obackgroundimage)
        olabel1.pack()
        oaddpwdbutton=Button(officeroot,width=12,height=3,text="ADD",font=('Arial',10),border=3,command=o_addpwd)
        oaddpwdbutton.place(x=50,y=100)

        omodifypwdbutton=Button(officeroot,width=12,height=3,text="MODIFY",font=('Arial',10),border=3,command=o_modpwd)
        omodifypwdbutton.place(x=50,y=200)

        ocopypwdbutton=Button(officeroot,width=12,height=3,text="COPY",font=('Arial',10),border=3,command=o_copypwd)
        ocopypwdbutton.place(x=50,y=300)

        obackbutton=Button(officeroot,text="Back",font=('Arial',10),fg='white',bg='black',border=3,command=oback)
        obackbutton.place(x=20,y=30)
        officeroot.mainloop()

    def mypwdrootwindow():
        def goback():
            mypwdroot.destroy()
            callmainwindow()
        global mypwdroot
        mypwdroot=Tk()
        mypwdroot.geometry("500x500+390+80")
        mypwdroot.minsize(500,500)
        mypwdroot.maxsize(500,500)
        mypwdroot.title("My Passwords")

        backgroundimage=PhotoImage(file='Images\mypwdimage.png')
        background=Label(mypwdroot,image=backgroundimage)
        background.pack()

        googleimage=PhotoImage(file='Images/googleimage.png')
        googlebutton=Button(mypwdroot,text="",width=90,height=95,image=googleimage,command=callgooglewindow)
        googlebutton.place(x=30,y=150)

        netfliximage=PhotoImage(file='Images/netfliximage.png')
        netflixbutton=Button(mypwdroot,text="",width=90,height=95,image=netfliximage,command=callnetflixwindow)
        netflixbutton.place(x=200,y=150)

        instaimage=PhotoImage(file='Images/instaimage.png')
        instabutton=Button(mypwdroot,text="",width=90,height=95,image=instaimage,command=callinstawindow)
        instabutton.place(x=370,y=150)

        linkedinimage=PhotoImage(file='Images/linkedinimage.png')
        linkedInbutton=Button(mypwdroot,text="",width=90,height=95,image=linkedinimage,command=calllinkwindow)
        linkedInbutton.place(x=30,y=350)

        facebookimage=PhotoImage(file='Images/facebookimage.png')
        facebookbutton=Button(mypwdroot,text="",width=90,height=95,image=facebookimage,command=callfacebookwindow)
        facebookbutton.place(x=200,y=350)

        officeimage=PhotoImage(file='Images/officeimage.png')
        officebutton=Button(mypwdroot,text="",width=90,height=95,image=officeimage,command=callofficewindow)
        officebutton.place(x=370,y=350)

        backbutton=Button(mypwdroot,text="Back",font=('Arial',10),fg='white',bg='black',border=3,command=goback)
        backbutton.place(x=20,y=10)

        mypwdroot.mainloop()

    mypwdrootwindow()

def strengthchecker():
        import re
        def goback():
            strengthcheckerroot.destroy()
            callmainwindow()

        def check_password_strength(password):
            score = 0
            
            # Length check
            if len(password) < 8:
                return "Weak", "Password should be at least 8 characters long."
            elif len(password) >= 8 and len(password) < 12:
                score += 1
            elif len(password) >= 12:
                score += 2
            
            # Complexity check
            if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
                score += 1
            if re.search(r"\d", password):
                score += 1
            if re.search(r"\W", password):
                score += 1
            
            # Strength evaluation
            if score < 3:
                return "Medium", "Password could be stronger. Add more complexity."
            elif score >= 3 and score < 5:
                return "Strong", "Password strength is good."
            elif score >= 5:
                return "Very Strong", "Password is very strong."

        def show_strength():
            password = password_entry.get()
            strength, feedback = check_password_strength(password)
            strength_label.config(text=strength, fg=get_strength_color(strength))
            feedback_label.config(text=feedback)

        def get_strength_color(strength):
            if strength == "Weak":
                return "red"
            elif strength == "Medium":
                return "orange"
            elif strength == "Strong":
                return "green"
            elif strength == "Very Strong":
                return "blue"

        # Create tkinter window
        strengthcheckerroot = Tk()
        strengthcheckerroot.title("Password Strength Checker")
        strengthcheckerroot.geometry("400x250+425+150")
        strengthcheckerroot.config(bg="#f0f0f0")

        # Header
        header_label = Label(strengthcheckerroot, text="Password Strength Checker", font=("Helvetica", 18, "bold"), bg="#f0f0f0")
        header_label.pack(pady=10)

        # Password Entry
        password_frame = Frame(strengthcheckerroot, bg="#f0f0f0")
        password_frame.pack(pady=5)
        password_label = Label(password_frame, text="Enter Password:", font=("Helvetica", 12), bg="#f0f0f0")
        password_label.grid(row=0, column=0, padx=(10, 5))
        password_entry = Entry(password_frame, show="*", font=("Helvetica", 12), bd=2, relief=SOLID)
        password_entry.grid(row=0, column=1, padx=(0, 10), pady=10)

        # Strength Label
        strength_label = Label(strengthcheckerroot, text="", font=("Helvetica", 14, "bold"), bg="#f0f0f0")
        strength_label.pack(pady=5)

        # Feedback Label
        feedback_label = Label(strengthcheckerroot, text="", font=("Helvetica", 12), bg="#f0f0f0", wraplength=380, justify="left")
        feedback_label.pack(pady=5)

        # Check Strength Button
        check_button = Button(strengthcheckerroot, text="Check Strength", font=("Helvetica", 12), command=show_strength, bg="#4caf50", fg="white", relief=FLAT)
        check_button.pack(pady=5)

        backbutton=Button(strengthcheckerroot,text="Back",font=('Arial',7),fg='white',bg='black',border=3,command=goback)
        backbutton.place(x=6,y=6)

        root.mainloop()
def callmainwindow():
    def callstrengthchecker():
        root.destroy()
        strengthchecker()
    def goback():
        root.destroy()
        loginwindow()
    global root
    root=Tk()
    root.geometry("610x510+325+80")
    root.minsize(610,500)
    root.maxsize(610,500)
    root.title("Password Manager")

    photo=PhotoImage(file='Images\Main image.png')
    mypwd=Label(root,image=photo)
    mypwd.pack()

    mypwdphoto=PhotoImage(file='Images\lock image.png')
    mybutton=Button(root,text="",font='Arial',width=130,height=130,image=mypwdphoto,border=3,command=callmypwd)
    mybutton.place(x=70,y=75)

    strengthphoto=PhotoImage(file='Images\strength image.png')
    strengthbutton=Button(root,text="",font='Arial',width=110,height=110,image=strengthphoto,border=3,command=callstrengthchecker)
    strengthbutton.place(x=400,y=250)

    generatephoto=PhotoImage(file='Images\generate image.png')
    generatebutton=Button(root,text="",font='Arial',width=110,height=110,image=generatephoto,border=3,command=callgeneratepwdwindow)
    generatebutton.place(x=400,y=20)

    backbutton=Button(root,text="Back",font=('Arial',10),fg='white',bg='black',border=3,command=goback)
    backbutton.place(x=20,y=10)
    root.mainloop()

def callnewuser(): 
    print(encryption_key)   
    def new_user_check():
        pwd = entry_new_password.get()
        cpwd = entry_confirm_password.get()
        nuser = entry_new_user.get()
        seckey = entry_security_key.get()
        
        if pwd == cpwd:
            # cipher = Fernet(encryption_key)
            # encrypted_password = cipher.encrypt(pwd.encode())
            cipher = Fernet(encryption_key)
            # encrypted_seckey = cipher.encrypt(seckey.encode())
            encrypted_password = cipher.encrypt(pwd.encode()).decode('utf-8')
            cipher = Fernet(encryption_key)
            encrypted_seckey = cipher.encrypt(seckey.encode()).decode('utf-8')
            cursor.execute("CREATE TABLE IF NOT EXISTS " + nuser + "(password VARCHAR(255) PRIMARY KEY, security_key VARCHAR(255), gpwd VARCHAR(255) DEFAULT NULL, npwd VARCHAR(255) DEFAULT NULL, ipwd VARCHAR(255) DEFAULT NULL, lpwd VARCHAR(255) DEFAULT NULL, fpwd VARCHAR(255) DEFAULT NULL, opwd VARCHAR(255) DEFAULT NULL)")
            cursor.execute("INSERT INTO " + nuser + "(password, security_key) VALUES ('" + encrypted_password + "','" + encrypted_seckey + "')")
            cursor.execute("COMMIT")
            new_user_window.destroy()

    # Create the new user window
    new_user_window = Tk()
    new_user_window.geometry('350x200+500+200')
    new_user_window.minsize(300, 200)
    new_user_window.maxsize(300, 200)
    new_user_window.title("Sign Up")
    new_user_window.configure(bg='#40E0D0')

    # Username label and entry
    label_new_user = Label(new_user_window, text='Enter username:', bg='#40E0D0')
    label_new_user.place(x=10, y=20)
    entry_new_user = Entry(new_user_window, font=('Open Sans', 10), border=3)
    entry_new_user.place(x=140, y=20, width=150)

    # Password label and entry
    label_new_password = Label(new_user_window, text='Enter password:', bg='#40E0D0')
    label_new_password.place(x=10, y=50)
    entry_new_password = Entry(new_user_window, font=('Open Sans', 10), border=3, show='*')
    entry_new_password.place(x=140, y=50, width=150)

    # Confirm password label and entry
    label_confirm_password = Label(new_user_window, text='Confirm password:', bg='#40E0D0')
    label_confirm_password.place(x=10, y=80)
    entry_confirm_password = Entry(new_user_window, font=('Open Sans', 10), border=3, show='*')
    entry_confirm_password.place(x=140, y=80, width=150)

    # Security key label and entry
    label_security_key = Label(new_user_window, text='Set Security Key:', bg='#40E0D0')
    label_security_key.place(x=10, y=110)
    entry_security_key = Entry(new_user_window, font=('Open Sans', 10), border=3, show='*')
    entry_security_key.place(x=140, y=110, width=150)

    # Signup button
    signup_button = Button(new_user_window, text="Signup", command=new_user_check)
    signup_button.place(x=125, y=150)

    new_user_window.mainloop()

def loginwindow():
    def check_user_exists():
        cursor.execute("""
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = %s
                AND table_name = %s
            )
        """, ('pythonmini', user))
        return cursor.fetchone()[0] == 1


    def check_password():

        global user
        user = entry_username.get()
        if check_user_exists():
            cursor.execute("SELECT password FROM " + user)
            fetched_pwd = cursor.fetchone()

            if fetched_pwd is not None:
                try:
                    cipher = Fernet(encryption_key)
                    fetchedpwd = cipher.decrypt(fetched_pwd[0].encode()).decode().strip()
                    global root_pwd
                    root_pwd = entry_password.get().strip()
                    if root_pwd == fetchedpwd:
                        login_window.destroy()
                        callmainwindow()
                        return
                    else:
                        messagebox.showerror('Error', 'Incorrect password! Please try again.')
                except Exception as e:
                    messagebox.showerror('Error', 'Failed to decrypt password: ' + str(e))
            else:
                messagebox.showerror('Error', 'No password found for user ' + user)
        else:
            messagebox.showerror('Error', 'User does not exist.')


    # Create the login window
    print(encryption_key)
    login_window = Tk()
    login_window.geometry('300x200+500+200')
    login_window.title("Login")
    login_window.configure(bg='#f7ed5c')

    # Username label and entry
    label_username = Label(login_window, text='Username:', bg='#f7ed5c')
    label_username.place(x=20, y=20)
    entry_username = Entry(login_window, font=('Open Sans', 10), border=3)
    entry_username.place(x=120, y=20)

    # Password label and entry
    label_password = Label(login_window, text='Password:', bg='#f7ed5c')
    label_password.place(x=20, y=60)
    entry_password = Entry(login_window, font=('Open Sans', 10), border=3, show='*')
    entry_password.place(x=120, y=60)

    # Login button
    login_button = Button(login_window, text="Login", command=check_password, bg='#4CAF50', fg='white')
    login_button.place(x=100, y=100, width=100)

    # Sign up button
    signup_button = Button(login_window, text="Sign Up", command=callnewuser, bg='#008CBA', fg='white')
    signup_button.place(x=100, y=140, width=100)

    login_window.mainloop()

loginwindow()

