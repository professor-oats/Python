# Python
Collection of Python scripts

## MyTeamsMonster
Project as part vocational education to learn how to consume API:s with Python.
Got the idea to build some code that will proxy the API between Teams and Gemini AI
to make some fun shenanigans.

## NetworkPy
Scripts related to generic networking. Testing some websocketing and more.

## ITHS_Labb1
Oat's Nmapper - A kind of wrapper for nmap.

### Tested on systems:
* FreeBSD

### Usage
Run the script with the permissions you'd want to run nmap, e.g.:<br/>
`sudo python nmapper.py`<br/>

Assign the amount of threads/maxworkers you'd like to run with
and chose to add targets manually or from file (support for comma/whitespace separated lists and JSON format).

Add the preset flags to the run and/or add your own flags.
Support for adding known nmap flags without hyphens as they will be normalized.
To see the full list of possible flags to use simply display all options.

When flags set press done to do the magic.

## ITHS_Labb2
Key with password generator + tool for encryption and decryption

### Tested on systems:
* Windows 10

### Usage
Create a key you want to use for encryption/decryption and optionally set a password.
Password is necessary to decrypt files.
`python keygen.py` <br/>

A prompt will be given to set password for use.

To encrypt file you point the script to the keyfilepath with `-k` flag,
and `-e` for encrypt, `-d` for decrypt:
`python crypto_tool.py -k [mykey] -e [filetoencrypt]` <br/>

To decrypt a file make sure that the extension `.encrypted` is used:
`python crypto_tool.py -k [mykey] -d [filetodecrypt].encrypted` <br/>

You can also generate a new key that is to be used for encryption/decryption by adding `-g` flag:
`python crypto_tool.py -g keyname` <br/>
can be used to encrypt on the fly:
`python crypto_tool.py -g keyname -e [filetoencrypt]`
