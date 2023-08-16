# Import necessary modules
import re
import sqlite3
import flet as ft
from flet import *
from cryptography.fernet import Fernet

# Create a text element for displaying login messages
login_message = ft.Text(visible=True, selectable=True, size=16)

# Define the function for the second page (tabs and password management)
def second_page(page2: ft.Page):
    # Function for handling tab changes
    def changetab(e):
        my_index = e.control.selected_index

        # Show/hide elements based on the selected tab
        tb1.visible = tb2.visible = tb3.visible = b.visible = t1.visible = (my_index == 0)
        tb8.visible = b4.visible = t2.visible = (my_index == 1)
        tb5.visible = tb6.visible = tb7.visible = b3.visible = t3.visible = (my_index == 2)
        tb4.visible = b2.visible = t4.visible = (my_index == 3)

        page2.update()

    # Initialize the navigation bar with tab options
    page2.navigation_bar = NavigationBar(
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
        ]
    )
    page2.update()

    # Establish a connection to the database
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    # Create the passwords table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        service TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        encryption_key TEXT NOT NULL
    );
    ''')
    conn.commit()

    # Function to generate a random encryption key
    def generate_key():
        key = Fernet.generate_key()
        return key

    # Function to encrypt a password using an encryption key
    def encrypt_password(password, key):
        fernet = Fernet(key)
        encrypted_password = fernet.encrypt(password.encode())
        return encrypted_password

    # Function to decrypt an encrypted password using an encryption key
    def decrypt_password(encrypted_password, key):
        fernet = Fernet(key)
        password = fernet.decrypt(encrypted_password).decode()
        return password

    # Function to add a password to the database
    def add_password(service, username, password):
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        key = generate_key()
        encrypted_password = encrypt_password(password, key)
        try:
            cursor.execute(
                "INSERT INTO passwords (service, username, password, encryption_key) VALUES (?, ?, ?, ?)",
                (service, username, encrypted_password, key)
            )
            conn.commit()
            t1.value = "Account added successfully!"
        except sqlite3.Error as e:
            t1.value = "An error occurred: " + str(e)
        finally:
            conn.close()

    # Function to retrieve and display a password
    def get_password(e):
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        service = tb4.value.lower()
        cursor.execute("SELECT * FROM passwords WHERE service=?", (service,))
        result = cursor.fetchone()
        if tb4.value == "":
            t4.value = "Enter an account!"
        elif result:
            password = decrypt_password(result[2], result[3])
            t4.value = "Username: " + result[1] + "\nPassword: " + password
        else:
            t4.value = "No password found for the specified service."
        conn.commit()
        conn.close()
        tb4.value = ""
        page2.update()

    # Function to modify an account's details
    def modify(e):
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        service = tb5.value.lower()
        new_username = tb6.value
        password = tb7.value

        if tb5.value == "" or tb6.value == "" or tb7.value == "":
            t3.value = "Complete all the fields."
        else:
            cursor.execute("SELECT * FROM passwords WHERE service=?", (service.lower(),))
            result = cursor.fetchone()
            if result:
                key = result[3]
                encrypted_password = encrypt_password(password, key)
                cursor.execute("UPDATE passwords SET username=?, password=? WHERE service=?", (new_username, encrypted_password, service))
                t3.value = "Account modified successfully!"
            else:
                t3.value = "Account not found."

        conn.commit()
        conn.close()

        tb5.value = ""
        tb6.value = ""
        tb7.value = ""
        page2.update()

    # Function to delete an account by service name
    def delete(service):
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        service = tb8.value.lower()
        cursor.execute("SELECT * FROM passwords WHERE service=?", (service.lower(),))
        result = cursor.fetchone()

        if tb8.value == "":
            t2.value = "Enter an account to delete."
        elif result:
            cursor.execute("DELETE from passwords WHERE service=?", (service.lower(),))
            t2.value = "Account deleted successfully!"
        else:
            t2.value = "Account not found."

        conn.commit()
        conn.close()
        tb8.value = ""
        page2.update()

    # Function to handle the submit button click
    def button_clicked(e):
        service = tb1.value.lower()
        username = tb2.value
        password = tb3.value
        if tb1.value == "":
            t1.value = "Complete all the fields."
        elif tb2.value == "":
            t1.value = "Complete all the fields."
        elif tb3.value == "":
            t1.value = "Complete all the fields."
        else:
            add_password(service, username, password)
            t1.value = "Password added."

        tb1.value = ""
        tb2.value = ""
        tb3.value = ""
        page2.update()

    # Create text elements
    t1 = ft.Text(visible=True, selectable=True, size=16)
    t2 = ft.Text(visible=True, selectable=True, size=16)
    t3 = ft.Text(visible=True, selectable=True, size=16)
    t4 = ft.Text(visible=True, selectable=True, size=16)

    # Create input fields for various purposes
    tb1 = ft.TextField(label="App or Service name", width=350, visible=True)
    tb2 = ft.TextField(label="Username", width=350, visible=True)
    tb3 = ft.TextField(label="Password ", password=True, can_reveal_password=True, width=350, visible=True)
    tb4 = ft.TextField(label="Find password", width=350, visible=False)
    tb5 = ft.TextField(label="Modify an account", width=350, visible=False)
    tb6 = ft.TextField(label="Change username", width=350, visible=False)
    tb7 = ft.TextField(label="Change password", password=True, can_reveal_password=True, width=350, visible=False)
    tb8 = ft.TextField(label="Delete an account", width=350, visible=False)

    # Create buttons for various actions
    b = ft.ElevatedButton(text="Submit", on_click=button_clicked)
    b2 = ft.ElevatedButton(text="Reveal Password", on_click=get_password, visible=False)
    b3 = ft.ElevatedButton(text="Modify", on_click=modify, visible=False)
    b4 = ft.ElevatedButton(text="Delete", on_click=delete, visible=False)

    # Add input fields and buttons to the page
    page2.add(
        Container(
            content=Column([
                tb1,
                tb2,
                tb3,
                b,
                t1,

                tb8,
                b4,
                t2,

                tb5,
                tb6,
                tb7,
                b3,
                t3,

                tb4,
                b2,
                t4,
            ])
        )
    )

    # Configure the page settings
    page2.title = "My Password Manager"
    page2.window_width = 385
    page2.window_height = 430
    page2.window_resizable = False
    page2.window_maximizable = False
    page2.scroll = "auto"
    page2.update()

# Main function for the initial login and registration screen
def main(page: ft.Page):
    # Function to generate a random encryption key for email password
    def generate_key2():
        key2 = Fernet.generate_key()
        return key2

    # Function to encrypt an email password using an encryption key
    def encrypt_email_password(email_password, key2):
        fernet = Fernet(key2)
        encrypted_email_password = fernet.encrypt(email_password.encode())
        return encrypted_email_password

    # Function to decrypt an encrypted email password using an encryption key
    def decrypt_email_password(encrypted_email_password, key2):
        fernet = Fernet(key2)
        email_password = fernet.decrypt(encrypted_email_password).decode()
        return email_password

    # Function to validate an email address using a regular expression
    def validate_email(email):
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None

    # Function to register a new account
    def register_account(email, email_password):
        conn2 = sqlite3.connect("accounts.db")
        cursor2 = conn2.cursor()

        # Check if the email already exists in the database
        cursor2.execute("SELECT email FROM accounts WHERE email = ?", (email,))
        result = cursor2.fetchone()

        if result:
            register_message.value = "Account already registered."
        else:
            key2 = generate_key2()
            encrypted_email_password = encrypt_email_password(email_password, key2)
            try:
                cursor2.execute("INSERT INTO accounts (email, email_password, email_password_encryption_key) VALUES (?, ?, ?)", (email, encrypted_email_password, key2))
                conn2.commit()
            except sqlite3.Error as e:
                register_message.value = "An error occurred: " + str(e)
            else:
                register_message.value = "Account registered successfully."
            finally:
                conn2.close()

    # Establish a connection to the accounts database
    conn2 = sqlite3.connect("accounts.db")
    cursor2 = conn2.cursor()

    # Create the accounts table if it doesn't exist
    cursor2.execute('''
    CREATE TABLE IF NOT EXISTS accounts (
        email TEXT PRIMARY KEY,
        email_password TEXT NOT NULL,
        email_password_encryption_key TEXT NOT NULL
    );
    ''')

    conn2.commit()

    # Function to handle the login process
    def login(email, email_password):
        conn2 = sqlite3.connect("accounts.db")
        cursor2 = conn2.cursor()
        cursor2.execute("SELECT email_password, email_password_encryption_key FROM accounts WHERE email = ?", (email,))
        result = cursor2.fetchone()
        if result:
            stored_password = result[0]
            email_password_encryption_key = result[1]
            decrypted_password = decrypt_email_password(stored_password, email_password_encryption_key)
            if email_password == decrypted_password:
                login_message.value = "Login Successfully" 
                page.window_destroy()
            else:
                login_message.value = "Incorrect password"
        else:
            login_message.value = "Email not found"
        conn2.close()

        return login_message.value

    # Function to handle the login button click
    def login_button_clicked(e):
        email = email_field.value.lower()
        email_password = email_password_field.value
        if email_field.value == "":
            login_message.value = "Complete all the fields."
        elif email_password_field.value == "":
            login_message.value = "Complete all the fields."
        elif not validate_email(email):
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
        if register_email_field.value == "":
            register_message.value = "Complete all the fields."
        elif register_password_field.value == "":
            register_message.value = "Complete all the fields."
        elif not validate_email(email):
            register_message.value = "Invalid email address."
        else:
            register_account(email, email_password)

        register_email_field.value = ""
        register_password_field.value = ""
        page.update()

    # Create input fields and buttons for login and registration
    email_field = ft.TextField(label="Email address", width=350, visible=True)
    email_password_field = ft.TextField(label="Password", password=True, can_reveal_password=True, width=350, visible=True)
    login_button = ft.ElevatedButton(text="Login", on_click=login_button_clicked, color="White")

    register_email_field = ft.TextField(label="Email address", width=350, visible=True)
    register_password_field = ft.TextField(label="Password", password=True, can_reveal_password=True, width=350, visible=True)
    register_button = ft.ElevatedButton(text="Register", on_click=register_button_clicked, color="White")
    register_message = ft.Text(visible=True, selectable=True, size=16)

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
                    login_message,
                ],
            )
        )

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
    page.scroll = "auto"
    page.update()

# Start the Flet app with the main function as the target
if __name__ == "__main__":
    ft.app(target=main)
    # If login is successful, navigate to the second_page function
    if login_message.value == "Login Successfully":
        ft.app(target=second_page)
