import json
import os
import re

# Configuration
calculate_security = True
results_dir = "/teamscale/teamscale_testing_files/teamscale_results_each_commit_diff_project_old_profile"
true_results_dir = "/teamscale/teamscale_testing_files/separated_data/java_time_split"

# Initialize counters
true_positive = 0  # TP
false_negative = 0  # FN
false_positive = 0  # FP
true_negative = 0  # TN
total_entries = 0
file_not_found = 0
security_entries = 0

# Function to clean text
def clean_text(text):
    """
    Cleans the text by removing extra spaces, newline characters, and tabs.
    """
    return re.sub(r'\s+', ' ', text.strip())

# Process all JSON files in the results directory
for file_name in os.listdir(results_dir):
    if not file_name.endswith(".json"):
        continue  # Skip non-JSON files

    result_path = os.path.join(results_dir, file_name)
    true_result_path = os.path.join(true_results_dir, file_name)

    try:
        # Load result data
        with open(result_path, 'r') as result_file:
            result_data = json.load(result_file)

        # Load true result data
        with open(true_result_path, 'r') as true_result_file:
            true_result_data = json.load(true_result_file)

        # Compare `extracted_content` from result entries with functions in true results
        for result_entry in result_data:
            total_entries += 1

            if calculate_security and result_entry.get("group1", "") not in [
                "Critical and Suspicious Statements",
                "Directory Traversal",
                "External Entities",
                "Hard-Coded Credentials",
                "Insufficient Authority Checks",
                "Weak Cryptography",
            ]:
                continue

            if calculate_security:
                security_entries += 1

            cleaned_extracted_content = clean_text(result_entry.get("extracted_content", ""))
            if not cleaned_extracted_content:
                print("No 'extracted_content' found in result entry. Skipping.")
                continue

            entry_file_exist = False
            for true_entry in true_result_data:
                cleaned_function_content = clean_text(true_entry.get("function", ""))
                label = true_entry.get("vulnerable", 0)

                if true_entry["file"] in result_entry["file_path"]:
                    entry_file_exist = True
                    prediction = int(cleaned_extracted_content in cleaned_function_content)

                    if prediction == 1 and label == 1:
                        true_positive += 1
                        break
                    elif prediction == 0 and label == 1:
                        false_negative += 1
                        break
                    elif prediction == 1 and label == 0:
                        false_positive += 1
                        break
                    elif prediction == 0 and label == 0:
                        true_negative += 1
                        break

            if not entry_file_exist:
                file_not_found += 1
                print(f"File not found in true result: {result_entry['file_path']}")

    except FileNotFoundError as e:
        print(f"File not found: {e}\n{result_path}\n{true_result_path}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
    except KeyError as e:
        print(f"Key error: {e}")

# Calculate metrics
precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) > 0 else 0
recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) > 0 else 0
accuracy = (true_positive + true_negative) / (
    true_positive + true_negative + false_positive + false_negative
) if (true_positive + true_negative + false_positive + false_negative) > 0 else 0
f03_score = (
    (1 + 0.3**2) * (precision * recall) / (0.3**2 * precision + recall)
    if (0.3**2 * precision + recall) > 0
    else 0
)
f1_score = (
    2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
)

# Print metrics
print(f"Total True Positives (TP): {true_positive}")
print(f"Total False Negatives (FN): {false_negative}")
print(f"Total False Positives (FP): {false_positive}")
print(f"Total True Negatives (TN): {true_negative}")
print(f"Total Entries: {total_entries}")
if calculate_security:
    print(f"Total Security Entries: {security_entries}")
print(f"Total Files Not Found: {file_not_found}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"Accuracy: {accuracy:.4f}")
print(f"f03_score: {f03_score:.4f}")
print(f"f1_score: {f1_score:.4f}")
