# Python program to read
# json file
import pandas
import sklearn
from sklearn.ensemble import RandomForestClassifier
import json
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, precision_score
import seaborn as sns
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import f1_score
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import os
from sklearn.inspection import permutation_importance
import matplotlib.pyplot as plt
from sklearn.tree import plot_tree


def GetImportantFeatures(X_train, y_train, X_test, y_test, names, plot=False):
    clf = RandomForestClassifier(n_estimators=100, max_depth=3)

    fig = plt.figure(figsize=(10, 10))

    # Meta-transformer for selecting features based on importance weights.
    sel = SelectFromModel(clf)
    sel.fit(X_train, y_train)

    selected_feat = X_train.columns[(sel.get_support())]

    rf = RandomForestRegressor(n_estimators=100, max_depth=3)
    rf.fit(X_train[selected_feat], y_train)

    plot_tree(rf.estimators_[0],
              feature_names=selected_feat,
              class_names=True,
              filled=True, impurity=True,
              rounded=True)

    fig.savefig('rf_individualtree.png')

    if (plot):
        perm = False

        if perm:
            result = permutation_importance(rf, X_train[selected_feat], y_train)

            sorted_idx = result.importances_mean.argsort()

            forest_importances = pd.Series(result.importances_mean[sorted_idx], index=selected_feat[sorted_idx])
            top_features = forest_importances.nlargest(15)
            fig, ax = plt.subplots()
            # forest_importances.plot.bar(yerr=result.importances_std, ax=ax)
            top_features.plot.bar(ax=ax)
            ax.set_title("Feature importances using permutation on full model")
            ax.set_ylabel("Mean accuracy decrease")

            fig.tight_layout()
            plt.show()

        else:

            feature_names = selected_feat
            tree_feature_importances = (
                rf.feature_importances_)
            sorted_idx = tree_feature_importances.argsort()

            y_ticks = np.arange(0, len(feature_names))
            fig, ax = plt.subplots()
            ax.barh(y_ticks, tree_feature_importances[sorted_idx])
            ax.set_yticks(y_ticks)
            ax.set_yticklabels(feature_names[sorted_idx])
            ax.set_title("Random Forest Feature Importances (MDI)")
            fig.tight_layout()
            plt.show()
    return selected_feat

def RandomForest(X_train, y_train, X_test, y_test, classNames):
    rf = RandomForestClassifier(n_estimators=100)

    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    scores = f1_score(y_test, y_pred, average=None)

    for i, j in zip(classNames, scores):
        print("{} f1-Score: {}".format(i, j))
    print(f1_score(y_test, y_pred, average="weighted"))

    precision = precision_score(y_test, y_pred, average=None, zero_division=1)
    for i, j in zip(classNames, precision):
        print("{} precision: {}".format(i, j))

    print("accuracy: {}".format(accuracy_score(y_test, y_pred)))

    plt.figure(figsize=(10, 10))
    fx = sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt=".2f", cmap="GnBu",xticklabels=classNames, yticklabels=classNames)

    plt.show()


# Opening JSON file


def main():
    # assign directory
    directory = '../TrainingData'
    writeDF = True

    # iterate over files in
    # that directory
    df = pandas.DataFrame()

    if (os.path.isfile(os.path.join(directory, 'out.zip'))):
        df = pd.read_csv(os.path.join(directory, 'out.zip'))
        writeDF = False
    else:
        for filename in os.listdir(directory):
            f = os.path.join(directory, filename)
            # checking if it is a file
            if os.path.isfile(f):
                df2 = pd.read_json(f, keep_default_dates=False)
                df2 = df2.T

                print("parsing " + f)

                if 'label' not in df2:
                    continue
                # Only keep rows that have labels
                df2 = df2[df2['label'].notna()]

                if df.empty:
                    df = df2
                else:
                    df = df.append(df2)

    if writeDF:
        # Convert NaN to 0.
        df = df.fillna(0)
        compression_opts = dict(method='zip',
                                archive_name='out.csv')
        df.to_csv(os.path.join(directory, 'out.zip'), index=False,
                  compression=compression_opts)

    for i in df:
        if len(df[i].unique()) == 1:
            print("dropped " + i)
            df = df.drop(columns=i)

    # If label has under 50 occurrences remove it
    counts = df['label'].value_counts()
    df = df.loc[df['label'].isin(counts.index[counts >= 50])]

    # Training the model on the training dataset
    # fit function is used to train the model using the training sets as parameters
    mapping = {k: v for v, k in enumerate(df.label.unique())}
    className = df["label"].unique()

    df['LabelInt'] = df.label.map(mapping)

    new_df = df._get_numeric_data()
    # creating a RF classifier
    # clf = RandomForestClassifier(n_estimators=100)
    train, test = train_test_split(new_df, test_size=0.2)

    label_train = train["LabelInt"]
    data_train = train.drop('LabelInt', axis=1)

    label_test = test["LabelInt"]
    data_test = test.drop('LabelInt', axis=1)

    features = GetImportantFeatures(data_train, label_train, data_test, label_test, className)
    RandomForest(data_train[features], label_train, data_test[features], label_test, className)


if __name__ == "__main__":
    main()
