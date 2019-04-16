Access Checker
==============================

What Is This?
-------------

This is a simple Python/Flask application intended to check if given access will be allowed or not via Cisco ACL(may contain hundreds of lines!!). This tool will take user inputs(Source IP, Source port, Protocol, Destination IP and Destination port) and will check against the user provided ACL and provide the result. This tool have both CLI and GUI options.


How To Install This
-------------------
1. Activate your Python virtual environment by following below steps
2. Run `pip3 install virtualenv`
3. Create a project directory and navigate to it
4. Create virtual environment by running `virtualenv -p python3 venv` 
5. Activate virtual environment by running `source venv/bin/activate`
More info [How To: Virtual environments](https://packaging.python.org/guides/installing-using-pip-and-virtualenv/)
6. Install this package by running `pip3 install access-checker-sbhalodia` 



How To Use This
---------------
CLI
------
1. Run the following command from cli
2. Example:
 `access-checker-cli -sip 10.1.1.10/24 -sport 22 -p tcp -dip 8.8.8.10/32 -dport 443 -f /Users/Mytestaccount/Desktop/myaclfile.acl` 


GUI
------
1. Run `access-checker-gui`

2. Navigate to http://localhost:5000 in your browser


Testing
-------

Best effort testing has been done. No thorough testing is completed. Please conduct your own testing before using this.

Note
-------

Please follow the exact input format as suggested in GUI and CLI.