from sklearn.model_selection import train_test_split
import CSVReader
import joblib
from sklearn.metrics import confusion_matrix 
data = CSVReader.read_csv("2darray.csv")
features = [ft[:-1] for ft in data]
values = [ft[-1] for ft in data]
X_train, X_test, y_train, y_test = train_test_split(features, values, test_size=0.3)
from sklearn.linear_model import LogisticRegression
from sklearn.datasets import make_classification
import time
start_time = time.time()

clf = LogisticRegression(random_state = 0).fit(X_train,y_train)

y_pred=clf.predict(X_test)

from sklearn import metrics

# Model Accuracy, how often is the classifier correct?
print("Accuracy:",metrics.accuracy_score(y_test, y_pred))
print("F1 Score: ", metrics.f1_score(y_test, y_pred))
tn, fp, fn, tp=(confusion_matrix(y_test, y_pred).ravel())
#print(tn,fp,fn,tp)
print("False Postive Rate: ",fp/(fp+tn))
print("False Negitve Rate: ",fn/(fn+tp))
print("True Negitive Rate: ",tn/(tn+fp))
print("True Positive Rate: ",tp/(tp+fn))
print(tp/(tp+fp))
