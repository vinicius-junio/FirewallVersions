# Palo Alto - API

## Contents:

<!--ts-->
   * [About](#about)
   * [Functionalities](#functionalities)
   * [Requisites](#requisites)
   * [How to Use](#how-to-use)
<!--te-->

About
============

API Palo Alto Project searches through IP's and returns System and License data from Firewalls.

Functionalities
============
- Reading IP's listing;

- At each API request a new API key is automatically generated;

- Get the data via API and direct it to a SQLite database;

- Get the SQLite Database Storage and add it to an XLSX file;

- URL or port not found error handling:
If a URL or PORT is wrong, it will generate the text file "error_firewall.log" which will be in the same directory as the Python Script.
Example Error log: 2022-01-22 19:33:34 WARNING Failed url: https://111.222.333.54:444" (the port 3 is missing);

- Excel file formatting:
Table Formatting, Table Name: "Firewall" and Sheet Name "Firewall";

- License module for consultation.

Requisites
============
- Must have a registered user on each firewall with "Superuser" permission and XML/API;

How To Use
============
- Insert the IP listing of the Firewalls in the "ip_list.txt" file;
- Insert the username and password with "Superuser" and (MXL/API) permissions in "main.py";
- Execute the Script to generate .xlsx file and SQLite database.







