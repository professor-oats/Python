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
Run script with same privileges as you would run nmap

# Tested on systems:
* FreeBSD

# USAGE
Run the script with the permissions you'd want to run nmap, e.g.:
`sudo python nmapper.py`
Assign the amount of threads/maxworkers you'd like to run with
and chose to add targets manually or from file (support for comma/whitespace separated lists and JSON format).

Add the preset flags to the run and/or add your own flags.
Support for adding known nmap flags without hyphens as they will be normalized.
To see the full list of possible flags to use simply display all options.

When flags set press done to do the magic.
