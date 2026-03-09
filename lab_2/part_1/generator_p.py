import random

def write_text(filename: str, text: str) -> str:
    """ function for write to file """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(text)    
    except PermissionError:
        print(f"Permission denied")
        exit(2)
    except Exception as e:
        print(e)
        exit(2)

def main() -> None:
    seq=""
    for i in range(128):
        seq+= str(random.randint(0,1))
    write_text("seq_p.txt", seq)

if __name__ == "__main__":
    main()
    
        