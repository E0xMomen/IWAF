import pandas as pd

# Load the final dataset
# fin = pd.read_csv("final.csv")

# # Normalize attack type labels in the 'Types' column
# fin["Types"].replace({
#     "sql": "SQLi",
#     "xss": "XSS",
#     "ssti": "SSTI",
#     "lfi": "LFI",
#     "shell": "RCE/Shell",
#     "nosql": "NoSQL",
#     "crlf": "CRLF",
#     "valid": "VALID",
#     "ssi": "SSI",
# }, inplace=True)

# # Drop duplicates and missing values
# fin.drop_duplicates(inplace=True)
# fin.dropna(inplace=True)

# final = fin.to_csv("final2.csv", index=False)

final = pd.read_csv("waf.csv")

print(final["Types"].value_counts())
print(final.info())
