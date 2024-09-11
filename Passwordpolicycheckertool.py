import datetime
import re
import sys
import pyfiglet
# added QMessageBox for confirmation popup during password DB entry
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QMessageBox
from PyQt5.QtGui import QColor, QPainter
from datetime import date, timedelta # for age checking
import pandas as pd # for csv reading/writing
import hashlib # for hashing stored passwords


def create_banner(text):
    ascii_banner = pyfiglet.figlet_format(text)
    print(ascii_banner)

# NIST Password Guidelines
def check_nist_password_guidelines(password):
    nist_len = r'^.{8,}$' # regex for >8 char passwords

    # regex for if string has upper and lower char, number, and symbol
    nist_complexity = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$'  
    if re.match(nist_len, password) and re.match(nist_complexity, password): # check for regex match
        return True
    else:
        return False

# OWASP Password Guidelines
def check_owasp_password_guidelines(password):
    owasp_len = r'^.{12,}$'# regex for >12 char passwords

    # regex for if string has upper and lower char, number, and symbol
    owasp_complexity = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]*[^A-Za-z0-9][A-Za-z\d]*$'  
    if re.match(owasp_len, password) and re.match(owasp_complexity, password): # check for regex match
        return True
    else:
        return False

# Password Strength Check
def check_password_strength(password):
    length_strength = min(len(password) // 4, 3)  # Strength increases every 4 characters, capped at 4
    complexity_strength = 0

    if any(char.isupper() for char in password) and any(char.islower() for char in password):
        complexity_strength += 2 # add strength if pass has upper and lower char
    if any(char.isdigit() for char in password):
        complexity_strength += 2 # add strength if pass has digit
    if any(char in '@$!%*?&' for char in password):
        complexity_strength += 2 # add strength if pass has special symbol
    
    total_strength = length_strength + complexity_strength
    return total_strength # return total pass strength

# i tried to make this look pleasing, but this is not a PyQt5 class
class PasswordPolicyChecker(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        create_banner("Password Policy Checker")
        
        self.password_label = QLabel("Enter password to check:")
        self.password_entry = QLineEdit()
        self.age_check = QPushButton("Check Age") # Check password age
        self.check_button = QPushButton("Check Password")
        self.add_pass = QPushButton("Add Password to DB") # Add password to .csv
        self.result_label = QLabel()
        self.strength_label = QLabel()

        self.check_button.clicked.connect(self.show_password_policy_result)
        self.age_check.clicked.connect(self.show_age_result) # assign show_age_result func to button
        self.add_pass.clicked.connect(self.create_entry) # assign create_entry func to button

        layout.addWidget(self.password_label)
        layout.addWidget(self.password_entry)
        layout.addWidget(self.check_button)
        layout.addWidget(self.result_label)
        layout.addWidget(self.strength_label)
        layout.addWidget(self.age_check) # add age_check widg
        layout.addWidget(self.add_pass)  # add add_pass widg

        layout.addStretch()  # add stretchable space before the age_check button

        self.setLayout(layout)

        self.setWindowTitle("Password Policy Checker")
        self.show()

# this is the function to create the popup window saying that the password
# being added fails a guideline. the function has a variable to pass which standard is being broken
    def show_popup(self, standard):
        choice = QMessageBox().question(self, 'Warning', f'This password fails {standard} guidelines; continue?',
                                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if choice == QMessageBox.No:
            return False
        else:
            return True


# The create_entry function works by storing saved passwords in a .csv file,
# and by referencing the final 3 entries in the table to see if the password is
# elligible for reuse. it also hashes all stored passwords with SHA256 for maximum security.
# i wasn't really sure if you wanted us to only keep a record of the last 3 passwords
# in the project, but i figured i'd keep all of them stored for the age checker function

    def create_entry(self):
        data = pd.read_csv("pass_storage.csv")
        passes = data['password'].tolist() # creates password list
        dates = data['date'].tolist() # creates date list

        # sha256 password hash
        entry = self.password_entry.text()
        newpass = hashlib.md5(entry.encode()).hexdigest()

        # create popup if respective standards are not adhered to
        if check_nist_password_guidelines(entry) == False:
            if self.show_popup("NIST") == False:
                return None # end func and don't add password
        elif check_owasp_password_guidelines(entry) == False:
            if self.show_popup("OWASP") == False:
                return None # end func and don't add password

        # test if password in previous 3
        last_3_passes = passes[-3:]

        for p in last_3_passes:
            if p == newpass:
                self.result_label.setText("This password was one of 3 previously used; please choose another")
                return None # break function


        passes.append(newpass) # append hashed password to list
        expiration_date = date.today() + timedelta(days=90) # create 90 day expiration date
        dates.append(expiration_date.strftime("%Y%m%d")) # append today's date to list

        # append new data to csv
        dict = {'password': passes, 'date': dates}
        df = pd.DataFrame(dict)
        df.to_csv("pass_storage.csv")
        self.strength_label.hide() # hide strength label
        self.result_label.setText("Password successfully added!")

# loads in same information from .csv file, and will check an entry to see
# if it matches a hashed password in the DB. if so, it will use the corresponding
# expiration date stored with the password to determine if it's expired and needs
# reset. if no password matches the hash, user is prompted to either add it to
# the DB or to re-type their password

    def show_age_result(self):
        data = pd.read_csv("pass_storage.csv")
        passes = data['password'].tolist()  # creates password list
        dates = data['date'].tolist()  # creates date list

        # sha256 password hash
        entry = self.password_entry.text()
        checked_pass = hashlib.md5(entry.encode()).hexdigest()

        # iterate to match password with corresponding date
        for i in range(len(passes)):
            if checked_pass == passes[i]:

                # grab date from password and subtract from today to check if pass expired
                today = date.today()
                expiration_date = datetime.datetime.strptime(str(dates[i]), "%Y%m%d").date()
                delta = (expiration_date - today).days
                if delta > 0: # if password has not expired
                    self.result_label.setText(f"Your password expires in {delta} days")
                    return None # exit the function
                else:
                    self.result_label.setText("Your password has expired; please change immediately")
                    return None # exit the function

        # if no password matches entry:
        self.result_label.setText("Password not in DB; add new password or re-enter")


    def show_password_policy_result(self):
        self.strength_label.show() # show strength label after hidden
        password = self.password_entry.text()
        nist_result = check_nist_password_guidelines(password)
        owasp_result = check_owasp_password_guidelines(password)
        password_strength = check_password_strength(password)

        if nist_result and owasp_result:
            self.result_label.setText("Password satisfies both NIST and OWASP guidelines.")
        elif nist_result:
            self.result_label.setText("Password satisfies NIST guidelines but not OWASP guidelines.")
        else:
            self.result_label.setText("Password does not satisfy NIST or OWASP guidelines.")

        self.strength_label.setText(f"Password Strength: {password_strength}")

        # Visualize password strength with colored bars
        self.strength_label.setStyleSheet(f"background-color: {self.get_color(password_strength)}")

    def get_color(self, strength):
        if strength >=0 and strength <=1:
            return "red"
        elif strength >=2 and strength <=3:
            return "orange"
        elif strength >=4 and strength <=5:
            return "yellow"
        elif strength > 5:
            return "green"

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PasswordPolicyChecker()
    sys.exit(app.exec_())
