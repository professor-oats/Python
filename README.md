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

### Tested on systems
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
Added functionalities so that a decryption counter is stored as an json object
linked to the filename that limits the numbers of decryptions to be made of an 
encrypted file.

Thoughtfully this could be further integrated into an admin sided key management system
that controls how many decryptions are to be allowed for a file.

SHA256-Check for file tamper also if the encrypted files has been tampered with or lost/changed data
in storage

### Tested on systems
* Windows 10

### Usage
Create a key you want to use for encryption/decryption and optionally set a password. <br/>
Password is necessary to decrypt files. <br/>
`python keygen.py` <br/>

A prompt will be given to set password for use.

To encrypt file you point the script to the keyfilepath with `-k` flag,
and `-e` for encrypt, `-d` for decrypt: <br/>
`python crypto_tool.py -k [mykey] -e [filetoencrypt]` <br/>

To decrypt a file make sure that the extension `.encrypted` is used: <br/>
`python crypto_tool.py -k [mykey] -d [filetodecrypt].encrypted` <br/>

To allow an encrypted file to be decrypted more times than one you specify it on encryption: <br/>
`python crypto_tool.py -k [mykey] -e [filetoencrypt] --max-decryptions=[int]` <br/>

You can also generate a new key that is to be used for encryption/decryption by adding `-g` flag: <br/>
`python crypto_tool.py -g keyname` <br/>

can be used to encrypt on the fly: <br/>
`python crypto_tool.py -g keyname -e [filetoencrypt]`
