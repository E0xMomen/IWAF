import pandas as pd

df = pd.read_csv("waf2.csv")

visualize_dataset = df['Types'].value_counts()
print(visualize_dataset)