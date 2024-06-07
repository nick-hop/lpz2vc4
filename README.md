# LPZ2VC4

LPZ2VC4 is a Python application designed to interact with a VC4 server. It uses PyQt5 for the GUI and the requests library to send HTTP requests to the server.

## Features

- Query the VC4 server for all programs
- Monitor a directory for changes and upload new programs to the server
- Save and load the authorization token and server IP address to a configuration file

## Windows Binary

A binary version of the application for windows is available in Releases. This binary is standalone and does not require Python or any other dependencies to be installed. You can run it by double-clicking on it in your file explorer.

## Todo
- Add ability to load new programs that do not yet exist on the server

## Installation

To install the dependencies for this project, you will need to have Python installed on your machine. Once Python is installed, you can install the dependencies by running the following command in your terminal:

```bash
pip install -r requirements.txt
```

This will install the following Python packages:

- PyQt5
- requests

## Usage

To run the application, navigate to the project directory in your terminal and run the following command:

```bash
python -m lpz2VC4.py
```

This will start the application. You will be prompted to enter your authorization token and the IP address of the VC4 server. These will be saved to a configuration file in your home directory for future use.

Your Authorization token will require 'Read-Write' priviledges

The application will monitor a directory of your choice for changes. When a new program is added to the directory, it will be uploaded to the VC4 server.

## Contributing

Contributions are welcome! Please feel free to submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.