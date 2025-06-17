import pandas as pd

# Load datasets for different attack types
sqli   = pd.read_csv("sqli_dataset.csv")
xss    = pd.read_csv("xss_dataset.csv")
ssti   = pd.read_csv("ssti_dataset.csv")
lfi    = pd.read_csv("lfi_dataset.csv")
shell  = pd.read_csv("shell_dataset.csv")
nosql  = pd.read_csv("NoSQL_dataset.csv")
crlf   = pd.read_csv("CRLF_dataset.csv")
final = pd.read_csv("final.csv")

# # Display basic information
print(sqli.info())
print(xss.info())

# # Check for null values
print(sqli.isnull().sum())
print(xss.isnull().sum())



# Add labels to each dataset (if not already present)
sqli["Types"]  = "SQLi"
xss["Types"]   = "XSS"
ssti["Types"]  = "SSTI"
lfi["Types"]   = "LFI"
shell["Types"] = "RCE/Shell"
nosql["Types"] = "NoSQL"
crlf["Types"]  = "CRLF"

# Concatenate all datasets
data = pd.concat([sqli, xss, ssti, lfi, shell, nosql, crlf,final], ignore_index=True)

# Final clean-up
data.dropna(inplace=True)
data.drop_duplicates(inplace=True)

#Save the final merged dataset
data.to_csv("waf.csv", index=False)

#Load and inspect the final dataset

# Load the final dataset

fin = pd.read_csv("waf.csv")

# Normalize attack type labels in the 'Types' column

print(fin.info())
print(fin["Types"].value_counts())


