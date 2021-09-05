#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Oct 15 01:13:39 2019

@author: Kash
"""

import pandas as pd
import matplotlib.pyplot as plt

#Read csv, select R1-R8 & populate data frame
dR = pd.read_csv('RIASEC Dataset.csv', delimiter='\t', usecols=['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8'])
#Remove values -1 from R1-R8
dR = dR.loc[(dR['R1'] >= 0) & (dR['R2'] >= 0) & (dR['R3'] >= 0) & (dR['R4'] >= 0) & (dR['R5'] >= 0) & (dR['R6'] >= 0) & (dR['R7'] >= 0) & (dR['R8'] >= 0)]
#Compute R Score (average of sum of R1 to R8)
dR['R Score'] = dR.sum(axis=1)/8
dtrain = dR[['R1','R Score']]

X = dtrain.iloc[:, :-1].values
y = dtrain.iloc[:, 1].values

#Split - train first 6500, test remaining
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2333, shuffle=False)

from sklearn.linear_model import LinearRegression
regressor = LinearRegression()
regressor.fit(X_train, y_train)

#4b Estimated Regression Function: ŷ = b0 + b1x
print()
print('ERF = ŷ = b0 + b1x =',regressor.intercept_,'+',regressor.coef_,'x')

from sklearn.metrics import mean_squared_error
y_pred = regressor.predict(X_train)

#4b RSS
msqe = mean_squared_error(y_pred,y_train)
print('RSS = ',msqe)

#Plot graph
plt.scatter(X_train, y_train, color = 'red')
plt.plot(X_train, regressor.predict(X_train), color = 'blue')
plt.title('R Score vs R1 (Training set)')
plt.xlabel('R1')
plt.ylabel('R Score')
plt.show()

#4c Test RSS
y_pred = regressor.predict(X_test)
msqe2 = mean_squared_error(y_pred,y_test)
print('RSS =',msqe2)
#0.520109

#plt.matshow(dtop.corr())
#plt.show()