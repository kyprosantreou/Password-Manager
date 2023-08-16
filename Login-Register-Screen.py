# Importing the Flet library and renaming it to ft for convenience
import re
import sqlite3
import flet as ft
from flet import *
from cryptography.fernet import Fernet

# Defining the main function which takes a Flet page as an argument
def main(page: ft.Page):

    def generate_key():
        # Generate a random key
        key=Fernet.generate_key()
        return key
    
    def encrypt_password(password, key):
        fernet = Fernet(key)
        encrypted_password = fernet.encrypt(password.encode())
        return encrypted_password
    
    def decrypt_password(encrypted_password, key):
        fernet = Fernet(key)
        password = fernet.decrypt(encrypted_password).decode()
        return password

    def validate_email(email):
        # Regular expression pattern for email validation
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None
    
    def register_account(email, password):
        conn = sqlite3.connect("accounts.db")
        cursor = conn.cursor()

        # Check if the email already exists in the database
        cursor.execute("SELECT email FROM accounts WHERE email = ?", (email,))
        result = cursor.fetchone()

        if result:
            register_message.value = "Account already registered."
        else:
            key = generate_key()  # Generate a random key for encryption
            encrypted_password = encrypt_password(password, key)  # Encrypting the password
            try:
                cursor.execute("INSERT INTO accounts (email, password, encryption_key) VALUES (?, ?, ?)", (email, encrypted_password, key))
                conn.commit()
            except sqlite3.Error as e:
                register_message.value = "An error occurred: " + str(e)
            else:
                register_message.value = "Account registered successfully."
            finally:
                conn.close()

    def login(email, password):
        conn = sqlite3.connect("accounts.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password, encryption_key FROM accounts WHERE email = ?", (email,))
        result = cursor.fetchone()
        if result:
            stored_password = result[0]
            encryption_key = result[1]
            decrypted_password = decrypt_password(stored_password, encryption_key)
            if password == decrypted_password:
                login_message.value = "Login Successfully"
            else:
                login_message.value = "Incorrect password"
        else:
            login_message.value = "Email not found"
        conn.close()

    def login_button_clicked(e):
        email = email_field.value.lower()
        password = password_field.value
        if email_field.value == "":
            login_message.value = "Complete all the fields."
        elif password_field.value == "":
            login_message.value = "Complete all the fields."
        elif not validate_email(email):
            login_message.value = "Invalid email address."
        else:
            login(email, password)

        email_field.value = ""
        password_field.value = ""
        page.update()

    def register_button_clicked(e):
        email = register_email_field.value.lower()
        password = register_password_field.value
        if register_email_field.value == "":
            register_message.value = "Complete all the fields."
        elif register_password_field.value == "":
            register_message.value = "Complete all the fields."
        elif not validate_email(email):
            register_message.value = "Invalid email address."
        else:
            register_account(email, password)

        register_email_field.value = ""
        register_password_field.value = ""
        page.update()

    # Connection to the database
    conn = sqlite3.connect("accounts.db")

    # Create a cursor for the database
    cursor = conn.cursor()

    # Create the database
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS accounts (
        email TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        encryption_key TEXT NOT NULL
    );
    ''')

    # Committing the data
    conn.commit()

    #Login screen assets
    email_field = ft.TextField(label="Email address", width=350, visible=True)
    password_field = ft.TextField(label="Password", password=True, can_reveal_password=True, width=350, visible=True)
    login_button = ft.ElevatedButton(text="Login", on_click=login_button_clicked,color="White")
    login_message = ft.Text(visible=True, selectable=True, size=16)

    #Register screen assets
    register_email_field = ft.TextField(label="Email address", width=350, visible=True)
    register_password_field = ft.TextField(label="Password", password=True, can_reveal_password=True, width=350, visible=True)
    register_button = ft.ElevatedButton(text="Register", on_click=register_button_clicked,color="White")
    register_message = ft.Text(visible=True, selectable=True, size=16)

    # Defining a function that will be called whenever the route changes
    def route_change(route):
        # Clearing all views from the page
        page.views.clear()

        # Creating a new view with an app bar and a button that takes the user to the "/Login" route
        page.views.append(
            ft.View(
                "/",
                [
                    ft.AppBar(title=ft.Text("Sign in",weight=ft.FontWeight.BOLD,color="White"),bgcolor="#1B2631"),
                    email_field,
                    password_field,
                    login_button,
                    ft.ElevatedButton("Don't have an account?", on_click=lambda _: page.go("/Register"),color="White"),
                    login_message,
                ],
            )
        )
        # If the current route is "/store", create a new view with an app bar and a button that takes the user back to the home route ("/")
        if page.route == "/Register":
            page.views.append(
                ft.View(
                    "/Register",
                    [
                        ft.AppBar(title=ft.Text("Register",weight=ft.FontWeight.BOLD,color="White"),bgcolor="#1B2631"),
                        register_email_field,
                        register_password_field,
                        register_button,
                        ft.ElevatedButton("Already have an account?", on_click=lambda _: page.go("/"),color="White"),
                        register_message,
                    ],
                )
            )
        # Update the page with the new views
        page.update()

    # Defining a function that will be called whenever a view is popped from the page
    def view_pop(view):
        # Remove the top view from the page's views list
        page.views.pop()
        # Get the new top view (which is the view that was just revealed by the pop) and navigate to its route
        top_view = page.views[-1]
        page.go(top_view.route)

    # Setting the page's route change callback to be the route_change function we defined above
    page.on_route_change = route_change
    # Setting the page's view pop callback to be the view_pop function we defined above
    page.on_view_pop = view_pop
    # Navigating to the page's current route
    page.go(page.route)

    page.title = "My Password Manager"  # The Window name
    page.window_width = 385  # window's width is 385 px
    page.window_height = 380  # window's height is 280 px
    page.window_resizable = False  # The window is not resizable
    page.window_maximizable = False  # The window is not maximizable
    page.scroll = "auto"  # Scroll
    page.update()

# Starting the Flet app with the main function as the target 
if __name__=="__main__":
    ft.app(target=main)
