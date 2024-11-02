import os
import re
import argparse
import json

BACKUP_FILE = "replacement.bk"

def replace_in_files(in_path, in_regex_pattern, in_replacement_text, backup=False):
  # Compile the regex pattern for efficiency
  pattern = re.compile(in_regex_pattern)
  changes = {}

  # Check if the path is a directory or a file
  if os.path.isdir(in_path):
    # Walk through all files in the directory and its subdirectories
    for root, _, files in os.walk(in_path):
      for file_name in files:
        file_path = os.path.join(root, file_name)
        process_file(file_path, pattern, changes, in_replacement_text, backup)
  elif os.path.isfile(in_path):
    process_file(in_path, pattern, changes, in_replacement_text, backup)
  else:
    print(f"{in_path} is neither a file nor a directory.")
    return

  # Save changes to the backup file if backup is enabled
  if backup and changes:
    with open(BACKUP_FILE, 'w', encoding='utf-8') as bk_file:
      json.dump(changes, bk_file)
    print(f"Backup saved to {BACKUP_FILE}")


def process_file(in_file_path, in_pattern, in_changes, in_replacement_text, backup):
  # Attempt to read the content of the file with UTF-8 encoding
  try:
    with open(in_file_path, 'r', encoding='utf-8') as file:
      content = file.read()
  except UnicodeDecodeError:
    print(f"Skipping {in_file_path}: Cannot decode as UTF-8.")
    return  # Skip this file if it can't be decoded as UTF-8
  except Exception as e:
    print(f"Error reading {in_file_path}: {e}")
    return  # Handle other potential errors gracefully

  # Check if there's a match in the file
  if in_pattern.search(content):
    # Save the original content in changes if backup is enabled
    if backup:
      in_changes[in_file_path] = content

    # Replace all occurrences of the regex pattern
    modified_content = in_pattern.sub(in_replacement_text, content)

    # Write the modified content back to the file
    with open(in_file_path, 'w', encoding='utf-8') as file:
      file.write(modified_content)

    print(f"Updated file: {in_file_path}")


def undo_changes():
  # Load the backup file if it exists
  if not os.path.exists(BACKUP_FILE):
    print("No backup file found. Nothing to undo.")
    return

  # Read the backup data
  with open(BACKUP_FILE, 'r', encoding='utf-8') as bk_file:
    changes = json.load(bk_file)

  # Restore each file to its original state
  for file_path, original_content in changes.items():
    with open(file_path, 'w', encoding='utf-8') as file:
      file.write(original_content)
    print(f"Restored file: {file_path}")

  # Remove the backup file after undoing changes
  os.remove(BACKUP_FILE)
  print(f"Undo completed. {BACKUP_FILE} has been deleted.")


def main():
  # Set up argparse for command-line arguments
  parser = argparse.ArgumentParser(description="Replace regex matches in files within a directory."
                                               "Enclose the match in quotes"
                                   "Default: regexmatch r'\r' (carriage return), replace_text='\n'")
  parser.add_argument("directory", help="Path to the directory or a single file to search in")
  parser.add_argument("regex_pattern", nargs='?', default=r'\^M', help="The regex pattern to search for")
  parser.add_argument("replacement_text", nargs='?', default='\n', help="The text to replace the pattern with")
  parser.add_argument("-r", action="store_true", help="Enable regex replacement mode:"
                                                      "'text_to_match' 'text_to_replace_with' (Leave empty replace for remove)")
  parser.add_argument("-u", action="store_true", help="Undo the previous replacement from backup")
  parser.add_argument("-b", action="store_true", help="Enable backup before replacement")

  args = parser.parse_args()

  if args.u:
    # Undo the previous changes using the backup file
    undo_changes()
  elif args.r:
    # Perform replacement with optional backup
    replace_in_files(args.directory, args.regex_pattern, args.replacement_text, backup=args.b)
  else:
    print("Please use the -r flag to enable replacement or -u to undo the last operation from backup.")


if __name__ == "__main__":
  main()
