import os
import re
import string
import csv

# ---------------- Utility ----------------

def find_files_with_prefix(prefix):
    return [
        f for f in os.listdir(".")
        if f.startswith(prefix) and os.path.isfile(f)
    ]


def is_mostly_text(data, threshold=0.9):
    printable = set(bytes(string.printable, "ascii"))
    count = sum(b in printable for b in data)
    return count / max(len(data), 1) > threshold


# ---------------- BIN → INTERMEDIATE TXT ----------------

def bin_to_txt(bin_file, out_file):
    with open(bin_file, "rb") as fin, open(out_file, "w", encoding="utf-8") as fout:
        while True:
            size_bytes = fin.read(4)
            if not size_bytes:
                break

            size = int.from_bytes(size_bytes, "big")
            if size == 0:
                continue

            payload = fin.read(size)
            if not payload:
                break

            if is_mostly_text(payload):
                text = payload.decode("utf-8", errors="replace")
            else:
                text = payload.hex(" ")

            text = "".join(c for c in text if c in string.printable)
            fout.write(text)


# ---------------- MERGE HELPERS ----------------

def compute_msg(args, fmt):
    out, j, i = "", 0, 0
    while i < len(fmt):
        if fmt[i] == '"':
            i+=1
        elif fmt[i] == "%" and j < len(args):
            out += args[j]
            j += 1
            i += 1
            if i < len(fmt) and fmt[i].isalpha():
                i += 1
        elif fmt[i]=="\\":
            if fmt[i+1]=="n" or fmt[i+1]=="t":
                i+=2

        else:
            out += fmt[i]
            i += 1
    return out


def load_format_file(csv_file):
    fmt = {}
    with open(csv_file, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sno = (row.get("Sno") or "").strip()
            if not sno:
                continue
            fname = (row.get("Filename") or "").strip()
            line_no = (row.get("Line") or "").strip()
            msg = (row.get("Message") or "")
            fmt[sno] = (fname, line_no, msg)
    return fmt


def merge_files(csv_file, txt_file, out_file):
    fmt_map = load_format_file(csv_file)

    with open(txt_file, "r") as fin, open(out_file, "w") as fout:
        for line in fin:
            parts = line.strip().split(",")
            if not parts:
                continue

            sno = None
            idx_pos = None
            for i, p in enumerate(parts):
                if p.startswith("sno="):
                    sno = p.split("=")[1]
                elif p.startswith("idx="):
                    idx_pos = i

            if sno in fmt_map and idx_pos is not None:
                ts = f"{parts[0]} {parts[1]}"
                fname, line_no, msg_fmt = fmt_map[sno]
                args = parts[idx_pos + 1:]
                msg = compute_msg(args, msg_fmt)
                fout.write(f"{ts:<30}{fname:<30}{line_no:<8}{msg}\n")


# ---------------- TAG EXTRACTION ----------------

def extract_tag_from_filename(file_1):
    """
    Extract TAG_* from filename
    """
    expected_l3_tag = ""
    c=0
    found = False
    i=0
    while i < len(file_1):
        if file_1[i]=='_' and found:
            c+=1
        if c == 6:
            break
        if file_1[i]=='T' or found:
            expected_l3_tag += file_1[i]
            found = True
        i+=1
    return expected_l3_tag

# ---------------- MAIN ----------------

if __name__ == "__main__":

    bin_files = [
        f for f in os.listdir(".")
        if f.startswith("L3_EVENT_BIN") and os.path.isfile(f)
    ]

    csv_files = [
        f for f in os.listdir(".")
        if f.lower().startswith("l3_messages_tag") and f.endswith(".csv")
    ]

    if not bin_files:
        print("No BIN files found.")
        exit(0)

    if not csv_files:
        print("No CSV format file found.")
        exit(1)

    csv_file = csv_files[0]
    csv_tag = extract_tag_from_filename(csv_file)

    for bin_file in bin_files:
        print(f"Processing file: {bin_file}")

        intermediate = f"intermediate_binary_{bin_file}.txt"
        bin_to_txt(bin_file, intermediate)

        with open(intermediate, "r") as f:
            first_line = f.readline().strip()

        if first_line != csv_tag:
            print(f"Mismatch of TAG for file: {bin_file}")
            print(f"Expected: {csv_tag}, Found: {first_line}")
            print("Skipping this file conversion.")
            print("-" * 50)
            os.remove(intermediate)
            continue

        output_file = bin_file.replace("BIN", "X")
        merge_files(csv_file, intermediate, output_file)

        os.remove(intermediate)
        print(f"Completed conversion for file: {bin_file}")
        print(f"Output written to: {output_file}")
        print("-" * 50)