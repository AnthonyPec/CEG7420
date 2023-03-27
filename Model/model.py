# Python program to read
# json file
from sklearn.ensemble import RandomForestClassifier
import json
import pandas as pd

# Opening JSON file
df = pd.read_json('../TrainingData/data.txt')
# returns JSON object as
# a dictionary

print(df)
# Iterating through the json
# list
# for i in data:
#     print(data[i])

