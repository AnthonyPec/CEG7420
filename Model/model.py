# Python program to read
# json file
import pandas
from sklearn.ensemble import RandomForestClassifier
import json
import pandas as pd

# Opening JSON file

# import required module
import os

# assign directory
directory = '../TrainingData'
print(os.getcwd())
# iterate over files in
# that directory
df = pandas.DataFrame()

for filename in os.listdir(directory):
    f = os.path.join(directory, filename)
    # checking if it is a file
    if os.path.isfile(f):
        df2 = pd.read_json(f)
        df2 = df2.T

        print("parsing " + f)

        if 'label' not in df2:
            continue
        # Only keep rows that have labels
        df2 = df2[df2['label'].notna()]

        if df.empty:
            df = df2
        else:
            # df.merge(df2, on='label', how='outer')
            df = df.append(df2)


# Convert NaN to 0.
df = df.fillna(0)

# creating a RF classifier
#clf = RandomForestClassifier(n_estimators=100)

# Training the model on the training dataset
# fit function is used to train the model using the training sets as parameters
# clf.fit(X_train, y_train)

# returns JSON object as
# a dictionary

print(df)


