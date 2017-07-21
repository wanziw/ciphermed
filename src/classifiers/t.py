import sys
import time
import numpy as np
import matplotlib.pyplot as plt
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

#Begining test
scale = float(sys.argv[1])
epilson = float(sys.argv[2])
alpha = float(scale / epilson)
acc = 0
testtime = 100
res1 = 0

#prepare test data
minmax_scale = preprocessing.MinMaxScaler()
w = np.copy(logreg.coef_[0])
x1 = np.zeros(modelsize) #original plaintext
for i in range(modelsize):
    x1[i] = np.random.uniform(alldata[i][1], alldata[i][0], 1)
xmin = np.amin(x1)
xdif = np.amax(x1) - np.amin(x1)

res1 = np.dot(x1, w)
#print(res1, ',', end='')

for _ in range(12):
    print(res1, ',', end='')
    scale *= 0.1
    alpha = scale / epilson
    acc = 0
    for _ in range(testtime):
        res2 = 0
        x2 = minmax_scale.fit_transform(x1)
        for i in range(modelsize):
            a = np.random.laplace( \
                    float(xmin * w[i] / xdif), \
                    float(alpha * np.absolute(w[i]) / epilson))
            res2 += x2[i] * w[i] + a

        res2 *= xdif

        print(res2, ',', end='')
        if np.sign(res1) == np.sign(res2):
            acc += 1

    print(1.0 * acc / testtime)
