import sys
import time
import numpy as np
from phe import paillier
from sklearn import linear_model, datasets, preprocessing

def sigmoid(x):
    return 1 / (1 + np.exp(-1.0 * x))

# import some data to play with
bc = datasets.load_breast_cancer()
X = bc.data
Y = bc.target

h = .02  # step size in the mesh

#training data
logreg = linear_model.LogisticRegression(C=1e5)
logreg.fit(X, Y)

#generate paillier key
public_key, private_key = paillier.generate_paillier_keypair()

#parse dataset
totalnum = 0
modelsize = 30
alldata = []
for i in range(modelsize):
    alldata.append([-np.inf, np.inf])

#Read test file
with open("./model/wdbc/wdbc.data", "r") as f:
    for line in f.readlines():
        xx = line.split(",")
        xx = xx[2:]
        xx = [float(i) for i in xx]

        for i in range(len(xx)):
            alldata[i][0] = np.maximum(alldata[i][0], xx[i])
            alldata[i][1] = np.minimum(alldata[i][1], xx[i])

#write information to file
f1 = open('model.out', 'w')
f2 = open('data.out', 'w')
for i in range(len(logreg.coef_[0])):
    f1.write(str(logreg.coef_[0][i]) + "\n")
    f2.write(str(alldata[i][0]) + " " + str(alldata[i][1]) + "\n")

#Begining test
scale = float(sys.argv[1])
epilson = float(sys.argv[2])
alpha = float(scale / epilson)
modelsize = 10
acc = 0
testtime = 1
res1 = 0

#prepare test data
minmax_scale = preprocessing.MinMaxScaler()
w = np.copy(logreg.coef_[0][:modelsize])
x1 = np.zeros(modelsize) #original plaintext
for i in range(modelsize):
    x1[i] = np.random.uniform(alldata[i][1], alldata[i][0], 1)
xmin = np.amin(x1)
xdif = np.amax(x1) - np.amin(x1)

res1 = np.dot(x1, w)
x1 = minmax_scale.fit_transform(x1)

ex1 = [public_key.encrypt(x) for x in x1]
exmin  = public_key.encrypt(xmin)
exdif  = public_key.encrypt(xdif)
exminn = public_key.encrypt(xmin / xdif)
exdiff = public_key.encrypt(1.0 / xdif)

for _ in range(10):
    scale *= 0.1
    alpha = scale / epilson
    for _ in range(testtime):
        res2 = public_key.encrypt(0)
        start = time.time()
        for i in range(modelsize):
            res2 += ex1[i] * w[i] + exminn * w[i] + \
                    np.random.laplace(0, \
                    float(alpha * np.absolute(w[i]) / epilson))
        end = time.time()
        res2 = private_key.decrypt(res2)
        res2 *= xdif

        print((end - start) * 1000, ',', end='')
        if np.sign(res1) == np.sign(res2):
            acc += 1
    print('')

#print(1.0 * acc / testtime)
