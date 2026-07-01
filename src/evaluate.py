import csv, os, sys

GROUND_TRUTH = "ground_truth.csv"
NOTICE_LOG = "notice.log"
WINDOW = 30.0  # a notice within this many seconds of the attack counts as catching it

# each injected attack should produce a matching zeek notice type
LABEL_TO_NOTE = {
    "UNAUTHORIZED_FC": "ModbusWatch::Unauthorized_Function_Code",
    "REGISTER_ENUMERATION": "ModbusWatch::Register_Enumeration",
    "SENSITIVE_REGISTER_WRITE": "ModbusWatch::Sensitive_Register_Write",
    "UNAUTHORIZED_CLIENT": "ModbusWatch::Unauthorized_Client",
}

def load_ground_truth(path):
    with open(path) as f:
        return [(float(r["timestamp"]), r["label"]) for r in csv.DictReader(f)]

def load_notices(path):
    # notice.log is tab-separated; the #fields line tells us which column is which
    notices, fields = [], None
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line and not line.startswith("#"):
                row = dict(zip(fields, line.split("\t")))
                notices.append((float(row["ts"]), row["note"]))
    return notices

def grade(gt, notices):
    matched, results = set(), []
    for atk_ts, label in gt:
        want = LABEL_TO_NOTE.get(label)
        hits = [i for i, (t, n) in enumerate(notices) if n == want and abs(t - atk_ts) <= WINDOW]
        matched.update(hits)
        results.append((label, len(hits) > 0, len(hits)))
    detected = sum(1 for _, ok, _ in results if ok)
    false_positives = len(notices) - len(matched)
    return results, detected, false_positives

def main():
    gt = load_ground_truth(GROUND_TRUTH)
    notices = load_notices(NOTICE_LOG)
    results, detected, false_positives = grade(gt, notices)

    print(f"{'attack class':<28}{'detected':>9}{'alerts':>8}")
    print("-" * 45)
    for label, ok, n in results:
        print(f"{label:<28}{('YES' if ok else 'NO'):>9}{n:>8}")
    print("-" * 45)
    print(f"detected {detected}/{len(gt)} attack classes, {false_positives} false positives")

    os.makedirs("results", exist_ok=True)
    with open("results/results.md", "w") as f:
        f.write("# ModbusWatch Detection Results\n\n")
        f.write(f"Detected **{detected} of {len(gt)}** injected attack classes with **{false_positives}** false positives.\n\n")
        f.write("| Attack class | Detected | Zeek alerts |\n|---|---|---|\n")
        for label, ok, n in results:
            f.write(f"| {label} | {'yes' if ok else 'no'} | {n} |\n")

    # fail the build if detection regressed, so CI catches broken rules
    if detected < len(gt) or false_positives > 0:
        print("FAIL: detection regressed")
        sys.exit(1)
    print("PASS: all attack classes detected, no false positives")

if __name__ == "__main__":
    main()
