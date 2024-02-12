import re
import time
import pyotp
import argon2
import random
import base64
import string
import smtplib
import secrets
import hashlib
import flet as ft
from flet import *
import mysql.connector
from cryptography.fernet import Fernet

# Main function for the initial login and registration screen
def main(page: ft.Page):

# Establish a connection to the MySQL database
    try:
        mydb = mysql.connector.connect(
            host="",
            user="",
            password="",
            database=""
        )
        cursor = mydb.cursor()

        # Create the passwords table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            service VARCHAR(255) NOT NULL,
            username VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL,
            id VARCHAR(255) NOT NULL
        );
        ''')

        # Create the accounts table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            email VARCHAR(255) PRIMARY KEY,
            email_password VARCHAR(255) NOT NULL,
            id VARCHAR(255) NOT NULL
        );
        ''')

        mydb.commit()

    except mysql.connector.Error as err:
        print("MySQL Error: {}".format(err))

    password_hasher = argon2.PasswordHasher()
    
    # Generate a random ID with a default length of 10 characters
    def generate_random_id(length=10):
        characters = string.ascii_letters + string.digits
        random_id = ''.join(secrets.choice(characters) for _ in range(length))
        return random_id
    
    def generate_otp(e):
        if register_email_field.value == "" or register_password_field.value == "":
            register_message.value = "Complete all the fields."
            return False  # Return False if fields are not complete
        else: 
            page.go("/OTP_Verification")

            secret_key = pyotp.random_base32()
            
            totp = pyotp.TOTP(secret_key,interval=60)
            email_totp=totp.now()
            global secret
            secret = secret_key

            OTP_email.value=email_totp
    
    def generate_otp2():
        secret_key2 = pyotp.random_base32()
        
        totp = pyotp.TOTP(secret_key2,interval=90)
        email_totp2=totp.now()
        global secret2
        secret2 = secret_key2

        OTP_email2.value=email_totp2


    def SUBMIT_OTP(e):
        input_code = OTP_text_field.value
        totp = pyotp.TOTP(secret,interval=60)

        if totp.verify(input_code):
            OTP_message.value = "OTP verified successfully."
            register_account(register_email_field.value, register_password_field.value)
            page.go("/Register")
            page.window_width = 385
            page.window_height = 385
            page.window_resizable = False
            page.window_maximizable = False
            register_email_field.value = ""
            register_password_field.value = ""
            OTP_text_field.value = ""
            page.update()
        else:
            OTP_message.value = "Wrong OTP code. Press Resend OTP button."
            OTP_text_field.value = ""
            page.update()

    def SUBMIT_OTP2(e):
        if OTP_text_field2.value == "": 
            OTP_message2.value = "Complete the OTP field with the OTP code you received in your email."
        else:
            input_code = OTP_text_field2.value
            totp = pyotp.TOTP(secret2,interval=90)

            if totp.verify(input_code):
                OTP_message2.value = "OTP verified successfully."
                page.go("/Forgot Password")
            else:
                OTP_message2.value = "Wrong OTP code. Press Send OTP button."
                OTP_text_field2.value = ""

        page.update()

    def send_email():
        sender_email = "pythoncyp@outlook.com"
        receiver_email = register_email_field.value
        sender_password = "apizza2002"

        smtp_server = "smtp-mail.outlook.com"
        smtp_port = 587

        try:
            with smtplib.SMTP(smtp_server, smtp_port) as smtp:
                smtp.starttls()
                smtp.login(sender_email, sender_password)

                subject = "One-Time Password"
                message = f"Your OTP is:{OTP_email.value} "
                email_body = f"Subject: {subject}\n\n{message}"
                smtp.sendmail(sender_email, receiver_email, email_body)
                OTP_message.value = "Email sent successfully!"
                page.update()
        except Exception as e:
            print(f"An error occurred: {e}")
    
    def otp_resend(e):
        secret_key = pyotp.random_base32()
            
        totp = pyotp.TOTP(secret_key,interval=90)
        email_totp=totp.now()
        global secret
        secret = secret_key

        OTP_email.value=email_totp
        send_email()
    
    def otp_send(e):
        # Get the email input value from the user
        email = write_your_email.value.strip()  # Remove leading/trailing spaces

        # Check if the email is empty
        if email == "":
            OTP_message2.value = "Please write your email."
        else:
            cursor = mydb.cursor()

            # Check if the email exists in the database
            cursor.execute("SELECT email FROM accounts WHERE email = %s", (email,))
            result = cursor.fetchone()

            if not result:
                OTP_message2.value = "This email is not registered."
            else:
                # Assuming generate_otp2 and send_email2 are defined and work correctly
                generate_otp2()
                send_email2()

        # Update the page
        page.update()

    def send_email2():
        if write_your_email.value == "":
            OTP_message2.value = "Please write your email."
        else:
            sender_email = "pythoncyp@outlook.com"
            receiver_email = write_your_email.value
            sender_password = "apizza2002"

            smtp_server = "smtp-mail.outlook.com"
            smtp_port = 587

            try:
                with smtplib.SMTP(smtp_server, smtp_port) as smtp:
                    smtp.starttls()
                    smtp.login(sender_email, sender_password)

                    subject = "One-Time Password"
                    message = f"Your OTP is: {OTP_email2.value} "
                    email_body = f"Subject: {subject}\n\n{message}"
                    smtp.sendmail(sender_email, receiver_email, email_body)
                    OTP_message2.value = "Email sent successfully!"
                    page.update()
            except Exception as e:
                print(f"An error occurred: {e}")

        page.update()

    def Confirm_Password(e):
        if new_password.value == "" or confirm_password.value == "":
            change_passsword_message.value = "Complete all the fields."
            page.update()
        elif new_password.value == confirm_password.value:
            cursor = mydb.cursor()
            n_password = confirm_password.value
            email = write_your_email.value
            cursor.execute("SELECT email_password FROM accounts WHERE email=%s", (email,))
            result = cursor.fetchone()
            if result:
                encrypted_email_password = password_hasher.hash(n_password)
                cursor.execute("UPDATE accounts SET email_password=%s WHERE email=%s", (encrypted_email_password, email))
                change_passsword_message.value = "Password changed successfully!"
                page.go("/")
                change_passsword_message.value = ""
                page.update()
        else:
            change_passsword_message.value = "The passwords don't match"
            page.update()
        
        mydb.commit()
        new_password.value = ""
        confirm_password.value = ""
        write_your_email.value = ""
        OTP_text_field2.value = ""
        OTP_message2.value = ""
        login_message.value = ""
        page.update()


    # Function for handling tab changes
    def changetab(e):
        my_index = e.control.selected_index

        # Show/hide elements based on the selected tab
        App_name_textfield.visible = username_textfield.visible = password_textfield.visible = b.visible = t1.visible =  (my_index == 0)
        delete_account_textfield.visible = b4.visible = t2.visible =  (my_index == 1)
        modify_account_textfield.visible = change_username_textfield.visible = change_passsword_textfield.visible = b3.visible = t3.visible = (my_index == 2)
        find_password_textfield.visible = b2.visible = t4.visible = show_all_accounts.visible = show_all_accounts_message.visible = (my_index == 3)
        user_text.visible = user_email.visible = user_password.visible = user_message.visible = submit.visible = sign_out.visible = delete_account_button.visible = (my_index == 4)

        page.update()
    
    # Function to register a new account
    def register_account(email, email_password):
        cursor = mydb.cursor()

        # Check if the email already exists in the database
        cursor.execute("SELECT email FROM accounts WHERE email = %s", (email,))
        result = cursor.fetchone()

        if result:
            register_message.value = "Account already registered."
        else:
            registration_id=generate_random_id()
            encrypted_email_password = password_hasher.hash(email_password)
            try:
                cursor.execute("INSERT INTO accounts (email, email_password,id) VALUES (%s, %s, %s)", (email, encrypted_email_password,registration_id))
                mydb.commit()
            except mysql.connector.Error as e:
                register_message.value = "An error occurred: " + str(e)
            else:
                register_message.value = "Account registered successfully. Sign in!"

    # Function to handle the login process
    def login(email, email_password):
        cursor = mydb.cursor()
        cursor.execute("SELECT email_password, id FROM accounts WHERE email = %s", (email,))
        result = cursor.fetchone()
        if result:
            stored_hashed_password = result[0]  # Get the stored hashed password from the database
            login_id = result[1]
            userID_text.value = login_id
            user_text.value = "UserID: " + login_id
            try:
                if password_hasher.verify(stored_hashed_password, email_password):  # Verify with the stored hash
                    login_message.value = "Login Successfully"
                    page.route = "/Password Management"
            except:
                    login_message.value = "Incorrect password."  # Display "Incorrect password" message here
        else:
            login_message.value = "Email not found."
        
        return login_message.value, userID_text.value
    
    def gen_fernet_key(passcode:bytes) -> bytes:
        assert isinstance(passcode, bytes)
        hlib = hashlib.md5()
        hlib.update(passcode)
        return base64.urlsafe_b64encode(hlib.hexdigest().encode('latin-1'))

    # Function to add a password to the database
    def add_password(service, username, password):
        cursor = mydb.cursor()
        user_id = userID_text.value
        
        passcode = username
        key = gen_fernet_key(passcode.encode('utf-8'))
        fernet = Fernet(key)
        encrypted_password = fernet.encrypt(password.encode('utf-8'))

        cursor.execute("SELECT service FROM passwords WHERE service=%s AND id=%s", (service, user_id))
        result = cursor.fetchone()

        if result:
            t1.value = "Service already registered for this user."
        else:
            try:
                cursor.execute(
                    "INSERT INTO passwords (service, username, password, id) VALUES (%s, %s, %s, %s)",
                    (service, username, encrypted_password, user_id)
                )

                mydb.commit()
                t1.value = "Account added successfully!"
            except mysql.connector.Error as e:
                t1.value = "An error occurred: " + str(e)

        App_name_textfield.value = ""
        username_textfield.value = ""
        password_textfield.value = ""
        page.update()

   # Function to retrieve and display a password
    def get_password(e):
        cursor = mydb.cursor()
        service = find_password_textfield.value.lower()
        user_id = userID_text.value

        cursor.execute("SELECT * FROM passwords WHERE service=%s AND id=%s", (service, user_id))
        result = cursor.fetchone()

        if find_password_textfield.value == "":
            t4.value = "Enter an account!"
        elif result:
            encrypted_password = result[2]  # Get the stored encrypted password from the database
            username = result[1]  # Get the username
            passcode = username
            try:
                key = gen_fernet_key(passcode.encode('utf-8'))
                fernet = Fernet(key)
                decrypted_password = fernet.decrypt(encrypted_password).decode('utf-8')
                
                t4.value = "Username: " + username + "\nPassword: " + decrypted_password
            except Exception as e:
                t4.value = "Error decrypting password: " + str(e)
        else:
            t4.value = "No username and password found for the specified service."
        find_password_textfield.value = ""
        page.update()

    # Function to modify an account's details
    def modify(e):
        cursor = mydb.cursor()
        service = modify_account_textfield.value.lower()
        new_username = change_username_textfield.value
        password = change_passsword_textfield.value
        user_id = userID_text.value

        if modify_account_textfield.value == "" or change_username_textfield.value == "" or change_passsword_textfield.value == "":
            t3.value = "Complete all the fields."
        else:
            cursor.execute("SELECT * FROM passwords WHERE service=%s AND id=%s", (service.lower(), user_id))
            result = cursor.fetchone()
            if result:
                passcode = new_username
                key = gen_fernet_key(passcode.encode('utf-8'))
                fernet = Fernet(key)
                encrypted_password = fernet.encrypt(password.encode('utf-8'))

                cursor.execute("UPDATE passwords SET username=%s, password=%s WHERE service=%s AND id=%s", (new_username, encrypted_password, service, user_id))
                t3.value = "Account modified successfully!"
            else:
                t3.value = "Account not found."

        mydb.commit()
        modify_account_textfield.value = ""
        change_username_textfield.value = ""
        change_passsword_textfield.value = ""
        page.update()

    def modify_user_account(e):
        cursor = mydb.cursor()
        new_email = user_email.value.lower()
        new_password = user_password.value

        if user_email.value == "" or user_password.value == "":
            user_message.value = "Complete all the fields."
        elif not email_validation(new_email):
            user_message.value = "Invalid email address."
        else:
            cursor.execute("SELECT * FROM accounts WHERE id=%s", (userID_text.value,))
            result = cursor.fetchone()
            if result:
                encrypted_email_password = password_hasher.hash(new_password)
                cursor.execute("UPDATE accounts SET email=%s, email_password=%s WHERE id=%s", (new_email, encrypted_email_password, userID_text.value))
                user_message.value = "Account modified successfully!"
            else:
                user_message.value = "Account not found."

        mydb.commit()
        user_email.value = ""
        user_password.value = ""
        page.update()
        page.update()

    def delete_account(e):
        cursor = mydb.cursor()
        user_id = userID_text.value

        try:
            cursor.execute("DELETE FROM accounts WHERE id=%s", (user_id,))
            mydb.commit()
            cursor.execute("DELETE FROM passwords WHERE id=%s", (user_id,))
            mydb.commit()
            user_message.value = "Account deleted successfully!"
            page.route = "/"

            t1.value = " "
            t2.value = " "
            t3.value = " "
            t4.value = " "
            user_text.value = " "
            user_message.value = " "
            login_message.value = " "
            register_message.value = " "

            close_dlg(e)
        except mysql.connector.Error as e:
            user_message.value = "An error occurred: " + str(e)

    def close_dlg(e):
        dlg_modal.open = False
        page.update()

    dlg_modal = ft.AlertDialog(
        modal=True,
        title=ft.Text("Please confirm"),
        content=ft.Text("Do you really want to delete your account permanently?"),
        actions=[
            ft.TextButton("Yes", on_click=delete_account),
            ft.TextButton("No", on_click=close_dlg),
        ],
        actions_alignment=ft.MainAxisAlignment.END,
        on_dismiss=lambda e: print("Modal dialog dismissed!"),
    )

    def open_dlg_modal(e):
        page.dialog = dlg_modal
        dlg_modal.open = True
        page.update()

    # Function to delete an account by service name
    def delete(e):
        cursor = mydb.cursor()
        service = delete_account_textfield.value.lower()
        user_id=userID_text.value
        cursor.execute("SELECT * FROM passwords WHERE service=%s AND id=%s", (service.lower(), user_id))
        result = cursor.fetchone()

        if delete_account_textfield.value == "":
            t2.value = "Enter an account to delete."
        elif result:
            cursor.execute("DELETE from passwords WHERE service=%s", (service.lower(),))
            t2.value = "Account deleted successfully!"
        else:
            t2.value = "Account not found."

        mydb.commit()

        delete_account_textfield.value = ""
        t4.value = ""
        page.update()
    
    # Function to handle the submit button click
    def button_clicked(e):
        service = App_name_textfield.value.lower()
        username = username_textfield.value
        password = password_textfield.value
        user_id=userID_text.value
        if App_name_textfield.value == "":
            t1.value = "Complete all the fields."
        elif username_textfield.value == "":
            t1.value = "Complete all the fields."
        elif password_textfield.value == "":
            t1.value = "Complete all the fields."
        else:
            add_password(service, username, password)

        App_name_textfield.value = ""
        username_textfield.value = ""
        password_textfield.value = ""
        page.update()

    #Function to display all the services 
    def show_all(e):
        cursor = mydb.cursor()
        try:
            user_id = userID_text.value
            cursor.execute("SELECT * FROM passwords WHERE id=%s ORDER BY service", (user_id,))
            result = cursor.fetchall()

            # Displaying results in a message
            if result:
                show_all_accounts_message.value = "\n\n".join([f"Service: {row[0]}" for row in result])
            else:
                show_all_accounts_message.value = "No services found for this user."
        except mysql.connector.Error as e:
            show_all_accounts_message.value = "An error occurred: " + str(e)

        page.update()

    # Function to validate an email address using a regular expression
    def email_validation(email):
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None
    
    # Function to handle the login button click
    def login_button_clicked(e):
        email = email_field.value.lower()
        email_password = email_password_field.value
        if email_field.value == "":
            login_message.value = "Complete all the fields."
        elif email_password_field.value == "":
            login_message.value = "Complete all the fields."
        elif not email_validation(email):
            login_message.value = "Invalid email address."
        else:
            login(email, email_password)
            email_field.value = ""
            email_password_field.value = ""

        page.update()

    # Function to handle the register button click
    def register_button_clicked(e):
        email = register_email_field.value.lower()
        email_password = register_password_field.value

        cursor = mydb.cursor()

        # Check if the email already exists in the database
        cursor.execute("SELECT email FROM accounts WHERE email = %s", (email,))
        result = cursor.fetchone()

        if result:
            register_message.value = "Account already registered."
        elif register_email_field.value == "":
            register_message.value = "Complete all the fields."
        elif register_password_field.value == "":
            register_message.value = "Complete all the fields."
        elif not email_validation(email):
            register_message.value = "Invalid email address."
        elif result:
            register_message.value = "Account already registered."
        else:
            generate_otp(e)
            send_email()

        page.update()

    def signout(route):
        page.route = "/"

        page.window_width = 385
        page.window_height = 385
        page.window_resizable = False
        page.window_maximizable = False
        page.update()

        t1.value = " "
        t2.value = " "
        t3.value = " "
        t4.value = " "
        user_text.value = " "
        user_message.value = " "
        login_message.value = " "
        register_message.value = " "
        login_message.value = " "
        register_message.value = " "

        page.update()

    # Create input fields and buttons for login and registration
    email_field = ft.TextField(label="Email address", width=350, visible=True)
    email_password_field = ft.TextField(label="Password", password=True, can_reveal_password=True, width=350, visible=True)
    login_button = ft.ElevatedButton(text="Login", on_click=login_button_clicked, color="White")
    login_message = ft.Text(visible=True, selectable=True, size=16)
    
    register_email_field = ft.TextField(label="Email address", width=350, visible=True)
    register_password_field = ft.TextField(label="Password", password=True, can_reveal_password=True, width=350, visible=True)
    register_button = ft.ElevatedButton(text="Register", on_click=register_button_clicked, color="White")
    register_message = ft.Text(visible=True, selectable=True, size=16)

    # Create text elements
    t1 = ft.Text(visible=True, selectable=True, size=16)
    t2 = ft.Text(visible=True, selectable=True, size=16)
    t3 = ft.Text(visible=True, selectable=True, size=16)
    t4 = ft.Text(visible=True, selectable=True, size=16)
    user_text = ft.Text(visible=False, selectable=True, size=16)
    userID_text = ft.Text(visible=False)
    user_message = ft.Text(visible=True, selectable=True, size=16)
    OTP_message = ft.Text(visible=True, selectable=True, size=16)
    OTP_message2 = ft.Text(visible=True, selectable=True, size=16)
    OTP_Header = ft.Text(visible=True, selectable=True, size=16, weight=FontWeight.W_500,
                    spans=[
                    ft.TextSpan(
                    "The OTP has sent to your email. Please complete the field.",
                    ft.TextStyle(decoration=ft.TextDecoration.UNDERLINE),
                )
            ]
        )
    OTP_Header2 = ft.Text(visible=True, selectable=True, size=16, weight=FontWeight.W_500,
                    spans=[
                    ft.TextSpan(
                    "Press send OTP to sent the code to your email. Please complete the field.",
                    ft.TextStyle(decoration=ft.TextDecoration.UNDERLINE),
                )
            ]
        )
    OTP_email = ft.Text(visible=False, selectable=True, size=16)
    OTP_email2 = ft.Text(visible=False, selectable=True, size=16)
    forgot_password = ft.Text(disabled=False,spans=[
                ft.TextSpan(
                    "Forgot Password?",
                    ft.TextStyle(decoration=ft.TextDecoration.UNDERLINE, weight=ft.FontWeight.BOLD),
                    on_click = lambda _: page.go("/OTP verification 2"),
                )
            ]
        )
    change_passsword_message = ft.Text(visible=True, selectable=True, size=16)
    show_all_accounts_message = ft.Text(visible=True, selectable=True, size=16)

    # Create input fields for various purposes
    App_name_textfield = ft.TextField(label="App or Service name", width=350, visible=True)
    username_textfield = ft.TextField(label="Username", width=350, visible=True)
    password_textfield = ft.TextField(label="Password ", password=True, can_reveal_password=True, width=350, visible=True)
    find_password_textfield = ft.TextField(label="Find password", width=350, visible=False)
    modify_account_textfield = ft.TextField(label="Modify an account", width=350, visible=False)
    change_username_textfield = ft.TextField(label="Change username", width=350, visible=False)
    change_passsword_textfield = ft.TextField(label="Change password", password=True, can_reveal_password=True, width=350, visible=False)
    delete_account_textfield = ft.TextField(label="Delete an account", width=350, visible=False)
    user_email = ft.TextField(label="New email", width=350, visible=False)
    user_password = ft.TextField(label="New Password", width=350, visible=False, can_reveal_password=True,password=True)
    OTP_text_field = ft.TextField(label="OTP", width=350, visible=True)
    OTP_text_field2 = ft.TextField(label="OTP", width=350, visible=True)
    new_password = ft.TextField(label="New Password", width=350, visible=True, can_reveal_password=True,password=True)
    confirm_password = ft.TextField(label="Confirm Password", width=350, visible=True, can_reveal_password=True,password=True)
    write_your_email = ft.TextField(label="Write your email", width=350, visible=True)

    # Create buttons for various actions
    b = ft.ElevatedButton(text="Submit", on_click=button_clicked)
    b2 = ft.ElevatedButton(text="Reveal Password", on_click=get_password, visible=False)
    b3 = ft.ElevatedButton(text="Modify", on_click=modify, visible=False)
    b4 = ft.ElevatedButton(text="Delete", on_click=delete, visible=False)
    sign_out = ft.ElevatedButton(text="Sign out", on_click=signout, visible=False)
    submit = ft.ElevatedButton(text="Submit", on_click=modify_user_account, visible=False)
    delete_account_button = ft.ElevatedButton(text="Delete account", on_click=open_dlg_modal, visible=False)
    resend_otp_button = ft.ElevatedButton(text="Resend OTP",visible=True , on_click=otp_resend)
    submit_otp = ft.ElevatedButton(text="Submit OTP",visible=True , on_click=SUBMIT_OTP)
    send_otp_button = ft.ElevatedButton(text="Send OTP",visible=True , on_click=otp_send)
    submit_otp2 = ft.ElevatedButton(text="Submit OTP",visible=True , on_click=SUBMIT_OTP2)
    confirm_password_button = ft.ElevatedButton(text="Confirm changes",visible=True , on_click=Confirm_Password)
    show_all_accounts = ft.ElevatedButton(text="Show all accounts", visible=False , on_click=show_all)

    sc = ft.Column(
        spacing=5,
        height=250,
        width=385,
        visible=True,
        scroll=ft.ScrollMode.ADAPTIVE,
    )

    sc.controls.append(App_name_textfield)
    sc.controls.append(username_textfield)
    sc.controls.append(password_textfield)
    sc.controls.append(b)
    sc.controls.append(t1)
    
    sc.controls.append(delete_account_textfield)
    sc.controls.append(b4)
    sc.controls.append(t2)

    sc.controls.append(modify_account_textfield)
    sc.controls.append(change_username_textfield)
    sc.controls.append(change_passsword_textfield)
    sc.controls.append(b3)
    sc.controls.append(t3)

    sc.controls.append(find_password_textfield)
    sc.controls.append(b2)
    sc.controls.append(t4)
    sc.controls.append(user_text)
    sc.controls.append(show_all_accounts)
    sc.controls.append(show_all_accounts_message)

    sc.controls.append(user_email)
    sc.controls.append(user_password)
    sc.controls.append(submit)
    sc.controls.append(user_message)
    sc.controls.append(sign_out)
    sc.controls.append(delete_account_button)
        
    # Function to handle route changes
    def route_change(route):
        page.views.clear()

        # Create a view for the login screen
        page.views.append(
            ft.View(
                "/",
                [
                    ft.AppBar(title=ft.Text("Sign in", weight=ft.FontWeight.BOLD, color="White"), bgcolor="#1B2631"),
                    email_field,
                    email_password_field,
                    login_button,
                    ft.ElevatedButton("Don't have an account?", on_click=lambda _: page.go("/Register"), color="White"),
                    forgot_password,
                    login_message,
                ],
            )
        )

        if page.route == "/":
            page.window_width = 385
            page.window_height = 385
            page.window_resizable = False
            page.window_maximizable = False
            page.theme_mode = ft.ThemeMode.DARK
            page.update()

        # Create a view for the registration screen
        if page.route == "/Register":
            page.views.append(
                ft.View(
                    "/Register",
                    [
                        ft.AppBar(title=ft.Text("Register", weight=ft.FontWeight.BOLD, color="White"), bgcolor="#1B2631"),
                        register_email_field,
                        register_password_field,
                        register_button,
                        ft.ElevatedButton("Already have an account?", on_click=lambda _: page.go("/"), color="White"),
                        register_message,
                    ],
                )
            )
        
        if page.route == "/OTP_Verification":
            page.window_width = 385
            page.window_height = 375
            page.window_resizable = False
            page.window_maximizable = False
            page.theme_mode = ft.ThemeMode.DARK
            page.update()
            page.views.append(
                ft.View(
                    "/OTP_Verification",
                    [
                        ft.AppBar(title=ft.Text("OTP Verification", weight=ft.FontWeight.BOLD, color="White"), bgcolor="#1B2631"),
                        OTP_Header,
                        OTP_text_field,
                        OTP_message,
                        submit_otp,
                        resend_otp_button
                    ],
                )
            )
        page.update()

        if page.route == "/Password Management":
            # Initialize the navigation bar with tab options
            page.navigation_bar = NavigationBar(
                bgcolor="#232323",
                on_change=changetab,
                selected_index=0,
                destinations=[
                    ft.NavigationDestination(icon=ft.icons.ADD, label="Add an\naccount"),
                    ft.NavigationDestination(icon=ft.icons.DELETE, label="Delete an\naccount"),
                    ft.NavigationDestination(
                        icon=ft.icons.CHANGE_CIRCLE_SHARP,
                        selected_icon=ft.icons.CHANGE_CIRCLE,
                        label="Modify an\naccount",
                    ),
                    ft.NavigationDestination(icon=ft.icons.SEARCH, label="Search"),
                    ft.NavigationDestination(icon=ft.icons.PERSON, label="Profile"),
                ]
            )

            page.update()
            
            page.views.append(
                ft.View(
                    "/Password Management",
                    [
                        page.navigation_bar,
                        ft.Container(sc),
                    ],
                )
            )

            page.window_width = 385
            page.window_height = 385
            page.window_resizable = False
            page.window_maximizable = False
            page.theme_mode = ft.ThemeMode.DARK
            
            page.update()

        if page.route == "/OTP verification 2":
            page.window_width = 385
            page.window_height = 425
            page.window_resizable = False
            page.window_maximizable = False
            page.theme_mode = ft.ThemeMode.DARK
            page.update()

            page.views.append(
                ft.View(
                    "/OTP verification 2",
                    [
                        ft.AppBar(title=ft.Text("Forgot Password", weight=ft.FontWeight.BOLD, color="White"), bgcolor="#1B2631"),
                        OTP_Header2,
                        write_your_email,
                        OTP_text_field2,
                        send_otp_button,
                        submit_otp2,
                        OTP_message2,
                    ],
                )
            )

        if page.route == "/Forgot Password":
            page.window_width = 385
            page.window_height = 330
            page.window_resizable = False
            page.window_maximizable = False
            page.update()

            page.views.append(
                ft.View(
                    "/Forgot Password",
                    [
                        ft.AppBar(title=ft.Text("Change Password", weight=ft.FontWeight.BOLD, color="White"), bgcolor="#1B2631"),
                        new_password,
                        confirm_password,
                        confirm_password_button,
                        change_passsword_message,
                    ],
                )
            )

        page.update()

    # Function to handle view pops
    def view_pop(view):
        page.views.pop()
        top_view = page.views[-1]
        page.go(top_view.route)

    page.on_route_change = route_change
    page.on_view_pop = view_pop
    page.go(page.route)

    # Configure the page settings
    page.title = "My Password Manager"
    page.window_width = 385
    page.window_height = 385
    page.window_resizable = False
    page.window_maximizable = False
    page.theme_mode = ft.ThemeMode.DARK
    page.update()

# Start the Flet app with the main function as the target
if __name__ == "__main__":
    ft.app(target=main)
