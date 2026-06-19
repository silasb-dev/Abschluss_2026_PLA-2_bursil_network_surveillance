#--------------------------------
# Author: Silas Burkhard
# Created: 26-06-11
# Last Changed: 26-06-11
# Description:
# Calculates my main
# Programm multiple times
# and visualize the result
#--------------------------------
import main.proto_1
import matplotlib.pyplot as plt 

f_positive = 0
f_negative = 0
correct = 0

n_runs = 100
i = 0


while i < n_runs:
    result = main.proto_1.run()
    correct += result.count("purple")
    f_positive += result.count("blue")
    f_negative += result.count("red")
    i += 1
    print(f"Round {i} done")


plt.bar(["Correct","False Positive","False Negative"],[correct,f_positive,f_negative])
plt.show()