import json


def write_bin_file(file_bin_path: str, data: bytes) -> None:
    """
    Write binary data to file

    args:
        file_bin_path: file to write
        data: binary data to write
    """
    try:
        with open(file_bin_path, "wb") as f:
            f.write(data)
    except OSError as e:
        raise OSError(f"Error writing to file {file_bin_path}: {e}") from e


def read_bin_file(file_bin_path: str) -> bytes:
    """
    Read binary data from file

    args:
        file_bin_path: file with data

    return:
        binary data
    """
    try:
        with open(file_bin_path, "rb") as f:
            return f.read()
    except FileNotFoundError as e:
        raise FileNotFoundError(f"File not found: {file_bin_path}") from e
    except OSError as e:
        raise OSError(f"Error reading file {file_bin_path}: {e}") from e


def read_json_file(file_path: str) -> dict:
    """
    Read JSON data from file

    args:
        file_path: path to JSON file

    return:
        dictionary with JSON data
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in file {file_path}: {e}") from e