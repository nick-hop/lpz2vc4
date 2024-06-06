import os
import time
import requests
import warnings
import datetime
from PyQt5.QtWidgets import QApplication, QDialog, QVBoxLayout, QPushButton, QComboBox, QLabel, QFileDialog,QTextEdit,QLineEdit
import sys
from PyQt5.QtCore import QThread, pyqtSignal, Qt

# Suppressing the warning
warnings.filterwarnings("ignore", message="Unverified HTTPS request")


# Function to query the VC4 server for all programs
def get_all_programs():
    headers = {
        'accept': 'application/json',
        'Authorization': auth_token
    }
    response = requests.get(api_endpoint, headers=headers, verify=False)  # Disabling SSL verification
    if response.status_code == 200:
        data = response.json()
        # Extract programs from the nested dictionary
        programs = data.get('Device', {}).get('Programs', {}).get('ProgramLibrary', {})
        # Ensure programs is a dictionary of dictionaries
        if isinstance(programs, dict) and all(isinstance(program, dict) for program in programs.values()):
            print("Retrieved Programs:")
            print(programs)  # Print all programs
            return list(programs.values())  # Return programs as a list of dictionaries
        else:
            print("Programs data is not in the expected format.")
            return None
    else:
        print(f"Failed to retrieve programs. Status code: {response.status_code}")
        return None

class MonitorThread(QThread):
    upload_time_signal = pyqtSignal(str)

    def __init__(self, directory, programs, combo_index, upload_log,api_endpoint):  
        super().__init__()
        self.directory = directory
        self.programs = programs
        self.combo_index = combo_index
        self.monitoring = True
        self.upload_log = upload_log
        self.api_endpoint = api_endpoint
    
    # Upload the file to the VC4 server
    def upload_file(self, file_path, file_name, program_id, friendly_name):
        # Construct the request headers
        headers = {
            'Authorization': auth_token
        }
        
        # Construct the request payload
        payload = {
            'ProgramId': program_id,
            'StartNow': 'true'
        }
        
        # Construct the file data
        files = {
            'AppFile': (file_name, open(os.path.join(file_path, file_name), 'rb'))
        }
        
        # Send the request
        response = requests.put(self.api_endpoint, headers=headers, data=payload, files=files, verify=False)
        
        # Check the response status code
        if response.status_code == 200:
            return "File uploaded successfully."
        else:
            return f"Failed to upload file. Status code: {response.status_code}"

        # Helper function to get the latest file in the directory
    def get_zip_file(self, directory):
        files = [os.path.join(directory, f) for f in os.listdir(directory) if f.endswith(".lpz")]
        if not files:
            return None
        zip_file = max(files, key=lambda x: os.path.getmtime(os.path.join(directory, x)))
        zip_file = zip_file.replace("/","\\")
        print("zipfile: ",zip_file)
        return zip_file

    def run(self):
        last_uploaded_time = 0
        while self.monitoring:
            zip_file = self.get_zip_file(self.directory)
            if zip_file:
                zip_file_time = os.path.getmtime(zip_file)
                if zip_file_time > last_uploaded_time:
                    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"\n\n[{current_time}] New file found: {os.path.basename(zip_file)}.")
                    chosen_program = self.programs[self.combo_index]
                    response = self.upload_file(self.directory, zip_file, chosen_program["ProgramId"], chosen_program["FriendlyName"])
                    if "Failed to upload file" in response:
                        print(response)  # Print error message
                    else:
                        print("File uploaded successfully.")
                        last_uploaded_time = zip_file_time
                        self.upload_time_signal.emit(current_time)
            else:
                print("No .zip files found in the directory.")
            time.sleep(10)  # Check every 10 seconds

    def stop(self):
        self.monitoring = False



class AuthIpDialog(QDialog):
    def __init__(self, auth_token=None, ip_address=None):
        super().__init__()

        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        self.setWindowTitle("Connection")

        self.layout = QVBoxLayout()

        self.auth_token_label = QLabel("AUTH_TOKEN:")
        self.auth_token_field = QLineEdit()
        if auth_token:
            self.auth_token_field.setText(auth_token)

        self.ip_address_label = QLabel("IP Address:")
        self.ip_address_field = QLineEdit()
        if ip_address:
            self.ip_address_field.setText(ip_address)

        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.accept)

        self.layout.addWidget(self.auth_token_label)
        self.layout.addWidget(self.auth_token_field)
        self.layout.addWidget(self.ip_address_label)
        self.layout.addWidget(self.ip_address_field)
        self.layout.addWidget(self.connect_button)

        self.setLayout(self.layout)

    def get_auth_token(self):
        return self.auth_token_field.text()

    def get_ip_address(self):
        return self.ip_address_field.text()   

# Main function to monitor the directory and upload new files
class MainWindow(QDialog):
    def __init__(self, programs,auth_token=None, api_endpoint=None):
        super().__init__()

        self.setWindowTitle("LPZ-2-VC4")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        
        self.programs = programs
        self.directory = None
        self.monitoring = False
        self.auth_token = auth_token
        self.api_endpoint = api_endpoint

        self.layout = QVBoxLayout()

        self.program_label = QLabel("Select a program:")
        self.program_combo = QComboBox()
        self.program_combo.addItems([program['FriendlyName'] for program in self.programs])

        self.directory_label = QLabel("Select a directory:")
        self.directory_button = QPushButton("Select Directory")
        self.directory_button.clicked.connect(self.select_directory)

        self.selected_directory_label = QLabel("")  

        self.monitor_button = QPushButton("Enable Monitor")
        self.monitor_button.clicked.connect(self.enable_monitor)

        self.upload_log = QTextEdit()  
        self.upload_log.setReadOnly(True)  

        self.version = QLabel("v1.0.0") 

        self.layout.addWidget(self.program_label)
        self.layout.addWidget(self.program_combo)
        self.layout.addWidget(self.directory_label)
        self.layout.addWidget(self.directory_button)
        self.layout.addWidget(self.selected_directory_label)   
        self.layout.addWidget(self.monitor_button)
        self.layout.addWidget(self.upload_log)  
        self.layout.addWidget(self.version) 

        self.setLayout(self.layout)

    def select_directory(self):
        self.directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if self.directory:
            print(f"Selected directory: {self.directory}")
            self.selected_directory_label.setText(f"Selected directory: {self.directory}")   

    def enable_monitor(self):
        if self.directory:
            if self.monitoring:
                self.monitor_thread.stop()
                self.monitoring = False
                self.monitor_button.setText("Enable Monitor")
                print("Monitoring disabled.")
            else:
                self.monitoring = True
                self.monitor_button.setText("Disable Monitor")
                self.monitor_thread = MonitorThread(self.directory, self.programs, self.program_combo.currentIndex(), self.upload_log, self.api_endpoint)
                self.monitor_thread.upload_time_signal.connect(self.update_upload_log)
                self.monitor_thread.start()
        else:
            print("No directory selected.")

    def update_upload_log(self, upload_time):
        self.upload_log.append(f"Last upload time: {upload_time}") 

   
if __name__ == "__main__":
    app = QApplication(sys.argv)

    home_dir = os.path.expanduser("~")
    lpz2vc4_dir = os.path.join(home_dir, '.lpz2vc4')
    os.makedirs(lpz2vc4_dir, exist_ok=True)

    auth_token_file = os.path.join(lpz2vc4_dir, 'settings.conf')

    auth_token = None
    ip_address = None
    if os.path.exists(auth_token_file):
        with open(auth_token_file, 'r') as file:
            auth_token, ip_address = file.read().strip().split(',')

    
    auth_ip_dialog = AuthIpDialog(auth_token, ip_address)
    if auth_ip_dialog.exec_() == QDialog.Accepted:
        auth_token = auth_ip_dialog.get_auth_token()
        ip_address = auth_ip_dialog.get_ip_address()
        with open(auth_token_file, 'w') as file:
            file.write(f"{auth_token},{ip_address}")
    else:
        sys.exit()
    
    api_endpoint = f"https://{ip_address}/VirtualControl/config/api/ProgramLibrary"


    programs = get_all_programs()

    if programs:
        window = MainWindow(programs, auth_token, api_endpoint)
        window.show()

    sys.exit(app.exec_())