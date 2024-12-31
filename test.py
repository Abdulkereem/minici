import os

def get_files_with_name_and_path(directory):
    """
    Get a list of dictionaries representing files in the given directory.
    Each dictionary contains the file name and its absolute path.

    Args:
        directory (str): The directory to list files from.

    Returns:
        list: A list of dictionaries with keys 'name' and 'path'.
    """
    try:
        # Normalize the directory path
        directory = os.path.abspath(directory)

        # Ensure the directory exists
        if not os.path.isdir(directory):
            raise ValueError(f"Provided path '{directory}' is not a valid directory.")

        # Get all files in the directory
        files = [
            {"name": item, "path": os.path.join(directory, item)}
            for item in os.listdir(directory)
            if os.path.isfile(os.path.join(directory, item))
        ]
        return files
    except Exception as e:
        print(f"Error retrieving files: {e}")
        return []


full_path = "/"
files = get_files_with_name_and_path(full_path)
print(files)
