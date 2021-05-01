from sklearn.model_selection import train_test_split
import CSVReader
from sklearn.metrics import confusion_matrix 
data = CSVReader.read_csv("dataset_withfeatures.csv")
features = [ft[:-1] for ft in data]
values = [ft[-1] for ft in data]
# Split dataset into training set and test set
X_train, X_test, y_train, y_test = train_test_split(features, values, test_size=0.3)


from sklearn.tree import DecisionTreeClassifier
clf = DecisionTreeClassifier()
clf.fit(X_train,y_train)
y_pred = clf.predict(X_test)
from sklearn import metrics

# Model Accuracy, how often is the classifier correct?
print("Accuracy:",metrics.accuracy_score(y_test, y_pred))
print("F1 Score: ", metrics.f1_score(y_test, y_pred))
tn, fp, fn, tp=(confusion_matrix(y_test, y_pred).ravel())
#print(tn,fp,fn,tp)
print("False Postive Rate: ",fp/(fp+tn))
print("False Negitve Rate: ",fn/(fn+tp))
print("True Negitive Rate: ",tn/(tn+fp))
print("True Positive Rate: ",tp/(tp+fn)) #Recall
print("precision",tp/(tp+fp))
